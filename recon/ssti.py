"""Offline SSTI evaluation ledger. No renderer, network client or exploit executor.

Probe outputs are candidates until two distinct bracketed arithmetic results and a
literal control are found on the SAME raw server-side surface, with submission
receipts. Browser-only rendering, incomplete captures and missing surfaces never
become a server-side proof or a negative verdict.

Depth rungs (`cred-read`, `token-use`, `lateral`) are also offline: they record
operator-supplied, hash-bound evidence under a campaign depth grant. They never
read a file, use a credential, resolve a host or move laterally.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from typing import Any, Dict, List
from urllib.parse import parse_qs, quote, urlsplit

from .callbacks import approved_callback_host, local_bytes, validate_callback_hosts
from .campaign import norm_host
from .extract import endpoint_key
from .fields import FieldLedger
from .store import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS ssti_sets(
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
  method TEXT NOT NULL, location TEXT NOT NULL, field TEXT NOT NULL,
  account TEXT NOT NULL, role TEXT NOT NULL DEFAULT '', tenant TEXT NOT NULL DEFAULT '',
  workflow TEXT NOT NULL DEFAULT '', seed TEXT NOT NULL UNIQUE, compact INTEGER NOT NULL,
  created TEXT NOT NULL,
  UNIQUE(asset_id, method, location, field, account, role, tenant, workflow));
CREATE TABLE IF NOT EXISTS ssti_surfaces(
  id INTEGER PRIMARY KEY, set_id INTEGER NOT NULL REFERENCES ssti_sets(id),
  kind TEXT NOT NULL, label TEXT NOT NULL, created TEXT NOT NULL,
  UNIQUE(set_id, kind, label));
CREATE TABLE IF NOT EXISTS ssti_observations(
  id INTEGER PRIMARY KEY, surface_id INTEGER NOT NULL REFERENCES ssti_surfaces(id),
  probe_id TEXT NOT NULL, source_kind TEXT NOT NULL, source_ref TEXT NOT NULL,
  sha256 TEXT NOT NULL, outcome TEXT NOT NULL, receipt INTEGER NOT NULL,
  created TEXT NOT NULL,
  UNIQUE(surface_id, probe_id, source_kind, source_ref, sha256));
CREATE TABLE IF NOT EXISTS ssti_case_events(
  id INTEGER PRIMARY KEY, surface_id INTEGER NOT NULL REFERENCES ssti_surfaces(id),
  case_id TEXT NOT NULL, state TEXT NOT NULL, severity TEXT NOT NULL DEFAULT '',
  grant TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
  exercise TEXT NOT NULL DEFAULT '', attempts INTEGER NOT NULL DEFAULT 0,
  note TEXT NOT NULL,
  created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ssti_event_artifacts(
  id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES ssti_case_events(id),
  path TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL,
  created TEXT NOT NULL,
  UNIQUE(event_id, path, sha256));
"""

SURFACE_KINDS = ("response", "view", "email", "export", "async", "dom")
DEPTH_GRANTS = ("context", "file-read", "execution")
DEPTH_CASES = {
    "cred-read": ("file-read", "high"),
    "token-use": ("execution", "critical"),
    "lateral": ("execution", "critical"),
}
CASES = ("detect", "confirm", "stored", "severity-gate") + tuple(DEPTH_CASES)
STATES = ("observed", "negative", "blocked", "inconclusive")
SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
READ_ONLY_METHODS = ("GET", "HEAD", "OPTIONS")
DATA_PATHS = (".env", "/proc/self/environ", "/metadata/",
              "/var/run/secrets/kubernetes.io/serviceaccount/token")
REDACTION_MARKERS = ("[redacted]", "<redacted>", "redacted")
SECRET_SIGNATURES = ("-----BEGIN ", "PRIVATE KEY", "AKIA")
MAX_EVENT_ARTIFACTS = 8
FAMILIES = {
    # A family is not an engine fingerprint. The same expression can be accepted
    # by several languages, renderers and frontend libraries.
    "braces": ("{{", "}}", ("Jinja2", "Twig", "Nunjucks", "Pebble", "Tornado", "Blade")),
    "dollar": ("${", "}", ("FreeMarker", "Mako", "JSP-EL", "Spring-EL")),
}
MAX_CAPTURE = 5_000_000
MAX_RECEIPTS = 500


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def granted_depths(config):
    """Read ssti.depth_grants: ["all"] or a subset of DEPTH_GRANTS, no repeats."""
    if not isinstance(config, dict):
        raise ValueError("ssti config must be an object")
    grants = config.get("depth_grants", [])
    if not isinstance(grants, list) or not all(isinstance(g, str) and g for g in grants):
        raise ValueError('ssti.depth_grants must be a list of grant names or ["all"]')
    unknown = [g for g in grants if g != "all" and g not in DEPTH_GRANTS]
    if unknown:
        raise ValueError(f"unknown ssti.depth_grants entries {unknown}; "
                         f"valid: {list(DEPTH_GRANTS)} or \"all\"")
    if len(set(grants)) != len(grants):
        raise ValueError("ssti.depth_grants must not repeat entries")
    return set(DEPTH_GRANTS) if "all" in grants else set(grants)


def depth_marker(seed: str, case_id: str) -> str:
    """Stable attempt marker for a depth rung; 32 lowercase hex characters."""
    return hashlib.sha256(f"{seed}:depth:{case_id}".encode()).hexdigest()[:32]


def probes(seed: str, compact: bool = False) -> Dict[str, Dict[str, Any]]:
    """Bounded, inert arithmetic and literal controls; no file, object or call access."""
    result = {}
    for family, (left, right, _) in FAMILIES.items():
        products = set()
        for variant in ("a", "b", "control"):
            key = f"{family}-{variant}"
            digest = hashlib.sha256(f"{seed}:{key}".encode()).digest()
            marker_len = 8 if compact else 16
            opening = "m" + hashlib.sha256(f"{seed}:open:{key}".encode()).hexdigest()[:marker_len]
            closing = "n" + hashlib.sha256(f"{seed}:close:{key}".encode()).hexdigest()[:marker_len]
            lhs, rhs = 510 + digest[0], 610 + digest[1]
            if variant != "control":
                while lhs * rhs in products:
                    lhs += 1
                products.add(lhs * rhs)
            expression = ("control" if variant == "control" else
                          f"{lhs}*{rhs}")
            text = ("literal-control" if variant == "control" else
                    f"{left}{expression}{right}")
            raw = opening + text + closing
            result[key] = {"id": key, "family": family, "variant": variant,
                           "opening": opening, "closing": closing, "raw": raw,
                           "url_encoded": quote(raw, safe=""),
                           "json_escaped": json.dumps(raw)[1:-1],
                           "expected": "literal-control" if variant == "control" else str(lhs * rhs)}
    return result


def classify(probe: Dict[str, Any], body: bytes, *, client_only: bool = False,
             complete: bool = True) -> str:
    """Classify only marker-bracketed output; never treat an error/status as proof."""
    if not complete or len(body) > MAX_CAPTURE:
        return "inconclusive"
    # Match the captured bytes, not a browser's HTML-entity decoding. An encoded
    # product in an HTML page is not a raw server-side evaluation proof.
    text = body.decode("utf-8", "replace")
    start, end = probe["opening"], probe["closing"]
    if start not in text or end not in text:
        return "absent"
    between = re.findall(re.escape(start) + "(.*?)" + re.escape(end), text, re.S)
    if not between:
        return "altered"
    if probe["variant"] == "control":
        return "control" if probe["expected"] in between else "altered"
    if probe["raw"] in text:
        return "literal"
    if probe["expected"] in between:
        return "client-evaluated" if client_only else "evaluated"
    return "altered"


class SstiLedger:
    def __init__(self, ctx):
        self.ctx = ctx
        self.db = ctx.store.db
        self.db.executescript(SCHEMA)
        self._migrate_sets()
        columns = {r["name"] for r in self.db.execute("PRAGMA table_info(ssti_case_events)")}
        for name, ddl in (
                ("severity", "TEXT NOT NULL DEFAULT ''"),
                ("grant", "TEXT NOT NULL DEFAULT ''"),
                ("target", "TEXT NOT NULL DEFAULT ''"),
                ("exercise", "TEXT NOT NULL DEFAULT ''"),
                ("attempts", "INTEGER NOT NULL DEFAULT 0")):
            if name not in columns:
                self.db.execute(f"ALTER TABLE ssti_case_events ADD COLUMN {name} {ddl}")
        self.db.commit()

    def _migrate_sets(self):
        """Upgrade the initial field-only key without discarding sets or child rows."""
        columns = {r["name"] for r in self.db.execute("PRAGMA table_info(ssti_sets)")}
        if {"role", "tenant", "workflow"} <= columns:
            return
        if not {"id", "asset_id", "method", "location", "field", "account", "seed",
                "compact", "created"} <= columns:
            raise ValueError("unrecognized SSTI set schema; migration refused")
        self.db.commit()
        self.db.execute("PRAGMA foreign_keys=OFF")
        try:
            self.db.executescript("""
BEGIN IMMEDIATE;
CREATE TABLE ssti_sets_new(
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
  method TEXT NOT NULL, location TEXT NOT NULL, field TEXT NOT NULL,
  account TEXT NOT NULL, role TEXT NOT NULL DEFAULT '', tenant TEXT NOT NULL DEFAULT '',
  workflow TEXT NOT NULL DEFAULT '', seed TEXT NOT NULL UNIQUE, compact INTEGER NOT NULL,
  created TEXT NOT NULL,
  UNIQUE(asset_id, method, location, field, account, role, tenant, workflow));
INSERT INTO ssti_sets_new(id,asset_id,method,location,field,account,seed,compact,created)
  SELECT id,asset_id,method,location,field,account,seed,compact,created FROM ssti_sets;
DROP TABLE ssti_sets;
ALTER TABLE ssti_sets_new RENAME TO ssti_sets;
COMMIT;
""")
        finally:
            if self.db.in_transaction:
                self.db.rollback()
            self.db.execute("PRAGMA foreign_keys=ON")
        if self.db.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("SSTI schema migration failed foreign-key validation")

    def _set(self, set_id):
        if type(set_id) is not int or set_id < 1:
            raise ValueError("set ID must be a positive integer")
        row = self.db.execute("SELECT * FROM ssti_sets WHERE id=?", (set_id,)).fetchone()
        if not row:
            raise ValueError(f"unknown SSTI set {set_id}")
        asset = self.ctx.store.get_asset(row["asset_id"])
        self.ctx.scope.check(asset["value"])
        return dict(row)

    def _surface(self, surface_id):
        if type(surface_id) is not int or surface_id < 1:
            raise ValueError("surface ID must be a positive integer")
        row = self.db.execute("SELECT * FROM ssti_surfaces WHERE id=?", (surface_id,)).fetchone()
        if not row:
            raise ValueError(f"unknown SSTI surface {surface_id}")
        return dict(row), self._set(row["set_id"])

    def _config(self):
        config = self.ctx.campaign.raw.get("ssti", {})
        if not isinstance(config, dict):
            raise ValueError("ssti config must be an object")
        return config

    def _granted(self):
        return granted_depths(self._config())

    def _callback_hosts(self):
        config = self._config()
        hosts = config.get("callback_hosts")
        if not hosts:
            ssrf = self.ctx.campaign.raw.get("ssrf", {})
            hosts = ssrf.get("callback_hosts", []) if isinstance(ssrf, dict) else []
        return validate_callback_hosts(hosts, "ssti.callback_hosts")

    def _has_observed(self, set_id, case_id):
        return bool(self.db.execute(
            "SELECT 1 FROM ssti_case_events e JOIN ssti_surfaces s ON s.id=e.surface_id "
            "WHERE s.set_id=? AND e.case_id=? AND e.state='observed' LIMIT 1",
            (set_id, case_id)).fetchone())

    def _observed_depth(self, surface_id):
        rows = self.db.execute(
            "SELECT DISTINCT case_id FROM ssti_case_events WHERE surface_id=? AND state='observed' "
            "AND case_id IN (" + ",".join("?" for _ in DEPTH_CASES) + ")",
            (surface_id, *DEPTH_CASES)).fetchall()
        return {r["case_id"] for r in rows}

    def _ceiling(self, surface_id, summary):
        observed = self._observed_depth(surface_id)
        if {"token-use", "lateral"} & observed:
            return "critical"
        if "cred-read" in observed:
            return "high"
        return "medium" if summary["confirmed_families"] else None

    def _keep_event_artifacts(self, artifacts):
        """Copy depth evidence into .recon/ssti-evidence/ and return hash references."""
        if not isinstance(artifacts, (tuple, list)) or len(artifacts) > MAX_EVENT_ARTIFACTS:
            raise ValueError("at most eight artifacts per depth event")
        if any(not isinstance(path, str) for path in artifacts):
            raise ValueError("artifact paths must be strings")
        if len(set(artifacts)) != len(artifacts):
            raise ValueError("artifact paths must be unique")
        blobs = [local_bytes(self.ctx.campaign.root, path) for path in artifacts]
        dest = self.ctx.campaign.state_dir / "ssti-evidence"
        if dest.is_symlink() or self.ctx.campaign.state_dir.is_symlink():
            raise ValueError("refusing a symlinked evidence store")
        kept = []
        for data in blobs:
            sha = _sha(data)
            dest.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = dest / sha
            if path.exists() or path.is_symlink():
                if path.is_symlink() or local_bytes(self.ctx.campaign.root, path.resolve()) != data:
                    raise ValueError("stored SSTI depth evidence was modified")
            else:
                with path.open("xb") as stream:
                    stream.write(data)
                path.chmod(0o600)
            kept.append({"path": path.relative_to(self.ctx.campaign.root).as_posix(),
                         "sha256": sha, "bytes": len(data)})
        return kept

    def _captured_contexts(self, asset_id, field, method, account, location,
                           observations=None):
        captured = set()
        for observation in (observations if observations is not None else
                            self.ctx.store.observations(asset_id)):
            params = observation["params"]
            bucket = ("body" if location in ("form", "json", "multipart") else location)
            if bucket == "path":
                names = (params.get("ids") or {}).keys()
            elif bucket in ("query", "body", "header", "cookie"):
                names = params.get(bucket) or []
            else:
                names = [name for key in ("query", "body", "header", "cookie")
                         for name in (params.get(key) or [])]
            if (observation["method"] or "").upper() != method or \
                    (observation["account"] or "") != account or \
                    field not in names:
                continue
            context = observation["context"]
            captured.add((context.get("role") or "", context.get("tenant") or "",
                          context.get("workflow_state") or ""))
        return captured

    def start(self, asset_id, field, method="", location="unknown", account="", compact=False,
              role="", tenant="", workflow=""):
        asset = FieldLedger(self.ctx)._asset(asset_id)
        if asset["kind"] != "endpoint":
            raise ValueError("SSTI sets require an endpoint")
        if not isinstance(field, str) or not 1 <= len(field) <= 300 or not isinstance(account, str):
            raise ValueError("field and account must be strings; field length 1..300")
        if any(not isinstance(v, str) or len(v) > 200 for v in (role, tenant, workflow, account)):
            raise ValueError("account/role/tenant/workflow must be strings of at most 200 characters")
        row = self.db.execute(
            "SELECT 1 FROM field_ledger WHERE asset_id=? AND field=? AND method=? AND "
            "location=? AND account=? AND case_id='ssti-eval'",
            (asset_id, field, method, location, account)).fetchone()
        if not row:
            raise ValueError("no matching field-ledger SSTI row; run fields sync or use its exact context")
        captured = self._captured_contexts(asset_id, field, method, account, location)
        selected = (role, tenant, workflow)
        if captured and selected not in captured:
            raise ValueError("role/tenant/workflow must match a capture for this field and account")
        if not captured and any(selected):
            raise ValueError("role/tenant/workflow requires a matching captured request")
        existing = self.db.execute(
            "SELECT id,compact FROM ssti_sets WHERE asset_id=? AND method=? AND location=? "
            "AND field=? AND account=? AND role=? AND tenant=? AND workflow=?",
            (asset_id, method, location, field, account, role, tenant, workflow)).fetchone()
        if existing:
            if bool(existing["compact"]) != bool(compact):
                raise ValueError("probe set already exists with a different compact setting")
            set_id = existing["id"]
        else:
            seed = secrets.token_hex(16)
            set_id = self.db.execute(
                "INSERT INTO ssti_sets(asset_id,method,location,field,account,role,tenant,workflow,"
                "seed,compact,created) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (asset_id, method, location, field, account, role, tenant, workflow,
                 seed, int(bool(compact)), now())).lastrowid
            self.db.execute("INSERT INTO ssti_surfaces(set_id,kind,label,created) "
                            "VALUES(?, 'response', 'submission response', ?)", (set_id, now()))
            self.db.commit()
            if len(captured) > 1:
                FieldLedger(self.ctx).record(asset_id, field, "ssti-eval", "probed", method,
                                             location, account, "Additional role/tenant/workflow context is open")
        return self.probes(set_id)

    def probes(self, set_id):
        row = self._set(set_id)
        surfaces = [dict(r) for r in self.db.execute(
            "SELECT * FROM ssti_surfaces WHERE set_id=? ORDER BY id", (set_id,))]
        return {"set_id": set_id, "asset_id": row["asset_id"], "field": row["field"],
                "method": row["method"], "location": row["location"], "account": row["account"],
                "role": row["role"], "tenant": row["tenant"], "workflow": row["workflow"],
                "probes": list(probes(row["seed"], bool(row["compact"])).values()),
                "surfaces": surfaces, "executed": False,
                "note": "Submit only on supplied test accounts under the campaign plan. "
                        "Each probe needs its own stored submission receipt; trace raw server responses."}

    def add_surface(self, set_id, kind, label):
        self._set(set_id)
        if kind not in SURFACE_KINDS or not isinstance(label, str) or not 1 <= len(label) <= 120 \
                or any(ord(c) < 32 for c in label):
            raise ValueError("invalid surface kind/label (label must be 1..120 single-line characters)")
        self.db.execute("INSERT OR IGNORE INTO ssti_surfaces(set_id,kind,label,created) "
                        "VALUES(?,?,?,?)", (set_id, kind, label, now()))
        self.db.commit()
        return dict(self.db.execute("SELECT * FROM ssti_surfaces WHERE set_id=? AND kind=? AND label=?",
                                    (set_id, kind, label)).fetchone())

    def _receipt_at(self, raw: str, row: Dict[str, Any], request_id: int) -> bool:
        """A request on the exact endpoint family/method carrying the probe."""
        from urllib.parse import unquote
        request = self.ctx.store.response(request_id)
        origin = self.ctx.store.get_asset(row["asset_id"])["value"]
        labels = request["context"]
        if any(key in labels and labels[key] != row[field] for key, field in
               (("account", "account"), ("role", "role"), ("tenant", "tenant"),
                ("workflow_state", "workflow"))):
            return False
        if not self.ctx.scope.is_in(request["url"]) or \
                not request["url"].startswith(("http://", "https://")) or \
                endpoint_key(request["url"]) != endpoint_key(origin) or \
                (row["method"] and request["method"] != row["method"]):
            return False
        if raw in unquote(request["url"]):
            return True
        payload = self.ctx.store.request_payload(request_id)
        if payload and payload["body_sha256"]:
            path = self.ctx.store.bodies_dir / payload["body_sha256"]
            if path.is_file():
                body = path.read_bytes()[:MAX_CAPTURE + 1]
                if len(body) <= MAX_CAPTURE and _sha(body) == payload["body_sha256"]:
                    return raw in unquote(body.decode("utf-8", "replace"))
        return False

    def _receipt(self, raw: str, row: Dict[str, Any], *, before_id=None,
                 strictly_before=False) -> int:
        """Find a stored submission; persist its ID so later verification is stable."""
        boundary = "id<?" if strictly_before else "id<=?"
        query = (f"SELECT id FROM requests WHERE {boundary} ORDER BY id DESC LIMIT ?" if
                 before_id is not None else "SELECT id FROM requests ORDER BY id DESC LIMIT ?")
        args = (before_id, MAX_RECEIPTS) if before_id is not None else (MAX_RECEIPTS,)
        for r in self.db.execute(query, args):
            if self._receipt_at(raw, row, r["id"]):
                return r["id"]
        return 0

    @staticmethod
    def _receipt_order(surface_kind, source_kind, source_ref, receipt):
        if not receipt:
            return True
        if source_kind == "artifact":
            return surface_kind != "response"
        response_id = int(source_ref)
        return (receipt == response_id if surface_kind == "response" else
                receipt <= response_id if surface_kind == "export" else
                receipt < response_id)

    def trace(self, surface_id, probe_id, *, response_id=None, artifact=None):
        surface, row = self._surface(surface_id)
        selected = probes(row["seed"], bool(row["compact"]))
        if probe_id not in selected:
            raise ValueError("unknown probe ID in this set")
        if (response_id is None) == (artifact is None):
            raise ValueError("specify exactly one stored response ID or campaign-local artifact")
        if surface["kind"] == "response" and artifact is not None:
            raise ValueError("submission response requires a stored response with its own request receipt")
        if response_id is not None:
            if type(response_id) is not int or response_id < 1:
                raise ValueError("response ID must be positive")
            resp = self.ctx.store.response(response_id)
            self.ctx.scope.check(resp["url"])
            path = self.ctx.store.bodies_dir / (resp["body_sha256"] or "missing")
            complete = resp["body_complete"] is True or resp["body_complete"] == 1
            body = path.read_bytes()[:MAX_CAPTURE + 1] if path.is_file() else b""
            if len(body) > MAX_CAPTURE:
                raise ValueError("stored response exceeds five megabytes; not classifiable")
            if resp["body_sha256"] and _sha(body) != resp["body_sha256"]:
                raise ValueError("stored response body hash mismatch")
            complete = complete and resp["body_sha256"] is not None and len(body) <= MAX_CAPTURE
            source_kind, source_ref = "response", str(response_id)
        else:
            if not isinstance(artifact, str):
                raise ValueError("artifact must be a campaign-relative file path")
            body = local_bytes(self.ctx.campaign.root, artifact)
            source_kind, source_ref = "artifact", artifact
            complete = True
        probe = selected[probe_id]
        outcome = classify(probe, body, client_only=surface["kind"] == "dom", complete=complete)
        if surface["kind"] == "response":
            receipt = response_id if self._receipt_at(probe["raw"], row, response_id) else 0
        else:
            receipt = self._receipt(probe["raw"], row, before_id=response_id,
                                    strictly_before=surface["kind"] != "export") if response_id else \
                      self._receipt(probe["raw"], row)
        sha = _sha(body)
        cur = self.db.execute(
            "INSERT OR IGNORE INTO ssti_observations(surface_id,probe_id,source_kind,source_ref,"
            "sha256,outcome,receipt,created) VALUES(?,?,?,?,?,?,?,?)",
            (surface_id, probe_id, source_kind, source_ref, sha, outcome, receipt, now()))
        if not cur.rowcount and receipt:
            self.db.execute("UPDATE ssti_observations SET receipt=? WHERE surface_id=? AND "
                            "probe_id=? AND source_kind=? AND source_ref=? AND sha256=? AND receipt=0",
                            (receipt, surface_id, probe_id, source_kind, source_ref, sha))
        self.db.commit()
        return {"observation_id": cur.lastrowid if cur.rowcount else None,
                "surface_id": surface_id, "probe_id": probe_id, "outcome": outcome,
                "submission_receipt": bool(receipt), "receipt_request_id": receipt or None,
                "sha256": sha, "new": bool(cur.rowcount),
                "executed": False, "finding_promoted": False}

    def _summary(self, surface, row):
        checks = probes(row["seed"], bool(row["compact"]))
        observations = [dict(r) for r in self.db.execute(
            "SELECT * FROM ssti_observations WHERE surface_id=? ORDER BY id", (surface["id"],))]
        latest = {o["probe_id"]: o for o in observations}
        evaluated = [key for key, o in latest.items() if o["outcome"] == "evaluated" and o["receipt"]]
        families = {key.split("-")[0] for key in evaluated}
        confirmed = sorted(family for family in families
                           if all(latest.get(f"{family}-{v}", {}).get("outcome") == "evaluated"
                                  and latest[f"{family}-{v}"]["receipt"] for v in ("a", "b"))
                           and latest.get(f"{family}-control", {}).get("outcome") == "control"
                           and latest[f"{family}-control"]["receipt"])
        negative = surface["kind"] in ("response", "view") and bool(latest) and all(
                                        k in latest and latest[k]["source_kind"] == "response" and
                                        latest[k]["receipt"] and
                                        latest[k]["outcome"] == ("control" if k.endswith("control") else "literal")
                                        for k in checks)
        events = [dict(e) for e in self.db.execute(
            "SELECT id,case_id,state,severity,grant,target,exercise,attempts,note,created "
            "FROM ssti_case_events WHERE surface_id=? ORDER BY id DESC LIMIT 20",
            (surface["id"],))]
        for event in events:
            event["event_id"] = event.pop("id")
            event["artifacts"] = [dict(a) for a in self.db.execute(
                "SELECT path,sha256,bytes FROM ssti_event_artifacts WHERE event_id=? ORDER BY id",
                (event["event_id"],))]
        return {"surface_id": surface["id"], "kind": surface["kind"], "label": surface["label"],
                "observations": len(observations), "outcomes": {k: o["outcome"] for k, o in latest.items()},
                "evaluated_families": sorted(families), "confirmed_families": confirmed,
                "negative": negative, "events": events,
                "depth_cases": sorted(self._observed_depth(surface["id"])),
                "severity_ceiling": self._ceiling(surface["id"],
                                                  {"confirmed_families": confirmed}),
                "missing_probes": sorted(set(checks) - set(latest))}

    def status(self, set_id):
        row = self._set(set_id)
        surfaces = [self._summary(dict(s), row) for s in self.db.execute(
            "SELECT * FROM ssti_surfaces WHERE set_id=? ORDER BY id", (set_id,))]
        integrity = self.verify(set_id)
        if not integrity["verified"]:
            # Do not continue advertising a proof whose stored bytes or receipts
            # have changed. The historical outcomes remain for investigation.
            for surface in surfaces:
                surface["confirmed_families"] = []
                surface["evaluated_families"] = []
                surface["negative"] = False
                surface["depth_cases"] = []
                surface["severity_ceiling"] = None
        return {"set_id": set_id, "asset_id": row["asset_id"], "field": row["field"],
                "account": row["account"], "role": row["role"], "tenant": row["tenant"],
                "workflow": row["workflow"],
                "surfaces": surfaces, "executed": False,
                "depth_grants": sorted(self._granted()),
                "integrity": integrity,
                "basis": "raw response/artifact marker matches plus stored submission receipts; "
                         "a syntax family is not a unique engine; each surface remains independent; "
                         "depth rungs are operator evidence under a written campaign grant"}

    def fingerprint(self, set_id):
        status = self.status(set_id)
        return {"set_id": set_id,
                "surfaces": [{"surface_id": s["surface_id"], "families": s["confirmed_families"],
                              "engine_candidates": {f: FAMILIES[f][2] for f in s["confirmed_families"]}}
                             for s in status["surfaces"]],
                "integrity": status["integrity"],
                "warning": "Shared syntax is not an engine/version/sandbox identification; no "
                           "execution or severity inference follows from arithmetic evaluation."}

    def plan(self, set_id):
        status = self.status(set_id)
        row = self._set(set_id)
        granted = self._granted()
        return {"set_id": set_id,
                "next": [{"surface_id": s["surface_id"], "probe_ids": s["missing_probes"]}
                         for s in status["surfaces"] if s["missing_probes"]],
                "confirmed_surfaces": [s["surface_id"] for s in status["surfaces"]
                                       if s["confirmed_families"]],
                "depth": {
                    "granted": sorted(granted),
                    "required": {case: grant for case, (grant, _) in DEPTH_CASES.items()},
                    "gates": {case: ("granted" if grant in granted else "grant-required")
                              for case, (grant, _) in DEPTH_CASES.items()},
                    "markers": {case: depth_marker(row["seed"], case)
                                for case in ("token-use", "lateral")},
                    "data_paths": list(DATA_PATHS),
                    "callback_hosts_configured": bool(self._callback_hosts()),
                    "read_only_methods": list(READ_ONLY_METHODS),
                    "ceiling": "critical after token-use/lateral; high after cred-read; "
                               "medium after evaluation only",
                    "note": "Depth cases record operator artifacts offline. They do not read "
                            "credentials, send a request, resolve a host or move laterally."},
                "integrity": status["integrity"], "executed": False}

    def _validate_depth(self, surface, row, case_id, state, grant, target, exercise,
                        attempts, artifacts, note, summary):
        required, _ = DEPTH_CASES[case_id]
        asset = self.ctx.store.get_asset(row["asset_id"])
        if grant != required:
            raise ValueError(f"{case_id} requires --grant {required}")
        if required not in self._granted():
            raise ValueError(f"{case_id} requires campaign ssti.depth_grants to include {required}")
        if not isinstance(target, str) or not 1 <= len(target) <= 2000 or \
                any(ord(c) < 32 or c.isspace() for c in target):
            raise ValueError("depth cases require a single-line --target (1..2000 characters)")
        if type(attempts) is not int or not 0 <= attempts <= 1:
            raise ValueError("depth attempts must be 0 or 1; retries need a new reviewed hypothesis")
        if not summary["confirmed_families"]:
            raise ValueError("depth rungs require a confirmed raw evaluation on this surface")
        if not isinstance(artifacts, (tuple, list)):
            raise ValueError("artifacts must be a list of campaign-local paths")
        texts = [local_bytes(self.ctx.campaign.root, p).decode("utf-8", "replace")
                 for p in artifacts]
        if case_id == "cred-read":
            if exercise not in (None, ""):
                raise ValueError("cred-read does not take --exercise")
            if not any(path in target.lower() for path in DATA_PATHS):
                raise ValueError(f"cred-read target must name a listed data path: {list(DATA_PATHS)}")
        elif case_id == "token-use":
            if exercise not in READ_ONLY_METHODS:
                raise ValueError(f"token-use requires a read-only --exercise: {list(READ_ONLY_METHODS)}")
            self.ctx.scope.check(target)
            parsed = urlsplit(target)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or \
                    parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise ValueError("token-use target must be a plain in-scope HTTP(S) URL")
            query_keys = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True)}
            if any(re.search(r"token|key|secret|password|session|auth", key) for key in query_keys):
                raise ValueError("token-use target must not embed credential-named query parameters; "
                                 "keep the value in the redacted artifact")
            marker = depth_marker(row["seed"], "token-use")
            if marker not in target.lower():
                raise ValueError(f"token-use target must carry the attempt marker {marker}")
            if not self._has_observed(row["id"], "cred-read"):
                raise ValueError("token-use requires an observed cred-read event on this set")
        else:
            if exercise not in (None, ""):
                raise ValueError("lateral does not take --exercise")
            host = norm_host(urlsplit(target).hostname if "://" in target else target)
            if not host or len(host) > 253 or any(c.isspace() for c in host):
                raise ValueError("lateral target must be a single callback hostname or URL")
            if not approved_callback_host(self._callback_hosts(), host):
                raise ValueError("lateral callback host has no explicit ssti.callback_hosts "
                                 "(or ssrf.callback_hosts) grant")
            render_host = norm_host(urlsplit(asset["value"]).hostname)
            if host == render_host or host.endswith("." + render_host) or \
                    render_host.endswith("." + host):
                raise ValueError("lateral callback host must differ from the render origin")
            marker = depth_marker(row["seed"], "lateral")
            if marker not in host:
                raise ValueError(f"lateral callback host must carry the attempt marker {marker}")
            if not self._has_observed(row["id"], "token-use"):
                raise ValueError("lateral requires an observed token-use event on this set")
        if state == "observed":
            if not artifacts:
                raise ValueError("observed depth evidence needs at least one artifact")
            if case_id == "cred-read" and len(
                    {_sha(local_bytes(self.ctx.campaign.root, p)) for p in artifacts}) < 2:
                raise ValueError("cred-read observed needs distinct evidence and control artifacts")
            if case_id in ("cred-read", "token-use") and not any(
                    marker in text.lower() for text in texts for marker in REDACTION_MARKERS):
                raise ValueError("cred-read/token-use evidence must show a redaction marker; "
                                 "never store a live credential")
            if case_id == "lateral" and not any(
                    depth_marker(row["seed"], "lateral") in text.lower() for text in texts):
                raise ValueError("lateral evidence must contain the bound attempt marker")
            if attempts != 1:
                raise ValueError("observed depth evidence requires exactly one declared attempt")
        if any(sig in text for text in texts for sig in SECRET_SIGNATURES) or \
                any(sig in note for sig in SECRET_SIGNATURES):
            raise ValueError("depth evidence or note contains an unredacted secret signature; "
                             "redact it first")
        return self._keep_event_artifacts(artifacts)

    def record(self, surface_id, case_id, state, note, severity=None, *, grant=None,
               target=None, exercise=None, attempts=0, artifacts=()):
        surface, row = self._surface(surface_id)
        if not self.verify(row["id"])["verified"]:
            raise ValueError("SSTI evidence failed integrity verification; run ssti verify")
        if case_id not in CASES or state not in STATES:
            raise ValueError("unknown SSTI case/state")
        if not isinstance(note, str) or not 1 <= len(note.strip()) <= 2000:
            raise ValueError("a 1..2000 character evidence note is required")
        if case_id == "severity-gate":
            if state != "observed" or severity not in SEVERITIES:
                raise ValueError("severity-gate requires observed and a severity")
        elif severity is not None:
            raise ValueError("--severity applies only to severity-gate")
        summary = self._summary(surface, row)
        kept = []
        if case_id in DEPTH_CASES:
            exercise = exercise.upper() if isinstance(exercise, str) else exercise
            kept = self._validate_depth(surface, row, case_id, state, grant, target, exercise,
                                        attempts, artifacts, note, summary)
        else:
            if any(v not in (None, "", 0, ()) for v in (grant, target, exercise, attempts)):
                raise ValueError("--grant/--target/--exercise/--attempts apply only to depth cases")
            if artifacts:
                raise ValueError("--artifact applies only to depth cases")
        if case_id == "severity-gate":
            if not summary["confirmed_families"]:
                raise ValueError("severity requires a confirmed raw evaluation with controls")
            ceiling = self._ceiling(surface_id, summary)
            if SEVERITY_RANK[severity] > SEVERITY_RANK[ceiling]:
                if ceiling == "medium":
                    raise ValueError("evaluation-only SSTI has a medium severity ceiling; "
                                     "read or execution impact is not proven by this workflow")
                raise ValueError(f"SSTI severity ceiling for this surface is {ceiling}; "
                                 f"{severity} is not supported by proven rungs")
        if state == "observed":
            if case_id == "detect" and not (summary["evaluated_families"] or summary["confirmed_families"]):
                raise ValueError("detect observed requires a raw evaluation and submission receipt")
            if case_id == "confirm" and not summary["confirmed_families"]:
                raise ValueError("confirm observed requires two distinct evaluations and a literal control")
            if case_id == "stored" and (surface["kind"] == "response" or not summary["confirmed_families"]):
                raise ValueError("stored observed requires confirmation on a different server-side surface")
        if state == "negative" and case_id not in DEPTH_CASES and not summary["negative"]:
            raise ValueError("negative requires every probe literal with receipts on this complete surface")
        cur = self.db.execute(
            "INSERT INTO ssti_case_events(surface_id,case_id,state,severity,grant,target,"
            "exercise,attempts,note,created) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (surface_id, case_id, state, severity or "", grant or "", target or "",
             exercise or "", attempts, note.strip(), now()))
        for ref in kept:
            self.db.execute(
                "INSERT INTO ssti_event_artifacts(event_id,path,sha256,bytes,created) "
                "VALUES(?,?,?,?,?)", (cur.lastrowid, ref["path"], ref["sha256"], ref["bytes"], now()))
        # An observation is not a finding. The field ledger is updated only after
        # the operator explicitly records a verified evaluation on this context.
        if case_id == "confirm" and state == "observed":
            contexts = self._captured_contexts(row["asset_id"], row["field"],
                                               row["method"], row["account"], row["location"])
            completed = 0
            for role, tenant, workflow in contexts:
                candidate = self.db.execute(
                    "SELECT id FROM ssti_sets WHERE asset_id=? AND method=? AND location=? "
                    "AND field=? AND account=? AND role=? AND tenant=? AND workflow=?",
                    (row["asset_id"], row["method"], row["location"], row["field"],
                     row["account"], role, tenant, workflow)).fetchone()
                if candidate and any(s["confirmed_families"] for s in
                                     self.status(candidate["id"])["surfaces"]):
                    completed += 1
            complete = not contexts or completed == len(contexts)
            FieldLedger(self.ctx).record(row["asset_id"], row["field"], "ssti-eval",
                                         "observed" if complete else "probed", row["method"],
                                         row["location"], row["account"],
                                         f"{note[:1900]} [SSTI captured contexts {completed}/{len(contexts)}]")
        self.db.commit()
        ceiling = self._ceiling(surface_id, self._summary(surface, row))
        return {"event_id": cur.lastrowid, "case": case_id, "state": state,
                "severity": severity, "severity_ceiling": ceiling,
                "grant": grant or "", "target": target or "", "exercise": exercise or "",
                "attempts": attempts, "artifacts": kept,
                "surface_id": surface_id, "finding_promoted": False, "executed": False}

    def verify(self, set_id=None):
        issues = []
        if set_id is not None:
            self._set(set_id)
        query = ("SELECT o.*,s.set_id,s.kind AS surface_kind FROM ssti_observations o "
                 "JOIN ssti_surfaces s ON s.id=o.surface_id")
        rows = self.db.execute(query + (" WHERE s.set_id=?" if set_id is not None else "") +
                               " ORDER BY o.id", (set_id,) if set_id is not None else ())
        for o in rows:
            try:
                row = self._set(o["set_id"])
                probe = probes(row["seed"], bool(row["compact"]))[o["probe_id"]]
                if o["source_kind"] == "response":
                    response = self.ctx.store.response(int(o["source_ref"]))
                    self.ctx.scope.check(response["url"])
                    if o["outcome"] not in ("inconclusive", "absent") and response["body_complete"] != 1:
                        raise ValueError("response is no longer a complete capture")
                    if response["body_sha256"]:
                        if response["body_sha256"] != o["sha256"]:
                            raise ValueError("response hash changed")
                        path = self.ctx.store.bodies_dir / response["body_sha256"]
                        data = path.read_bytes()[:MAX_CAPTURE + 1]
                    else:
                        if response["body_len"] or o["outcome"] != "inconclusive":
                            raise ValueError("response body unavailable")
                        data = b""
                    complete = response["body_complete"] == 1 and bool(response["body_sha256"])
                else:
                    if o["surface_kind"] == "response":
                        raise ValueError("submission response must cite its own stored request")
                    data = local_bytes(self.ctx.campaign.root, o["source_ref"])
                    complete = True
                if _sha(data) != o["sha256"]:
                    raise ValueError("artifact hash changed")
                if classify(probe, data, client_only=o["surface_kind"] == "dom",
                            complete=complete) != o["outcome"]:
                    raise ValueError("classification no longer matches raw capture")
                if not self._receipt_order(o["surface_kind"], o["source_kind"],
                                           o["source_ref"], o["receipt"]):
                    raise ValueError("submission receipt is unrelated to or later than the surface")
                if o["receipt"] and not self._receipt_at(probe["raw"], row, o["receipt"]):
                    raise ValueError("submission receipt missing or changed")
            except (OSError, ValueError, KeyError) as exc:
                issues.append({"observation_id": o["id"], "error": str(exc)})
        artifacts = self.db.execute(
            "SELECT a.*,s.set_id FROM ssti_event_artifacts a "
            "JOIN ssti_case_events e ON e.id=a.event_id "
            "JOIN ssti_surfaces s ON s.id=e.surface_id"
            + (" WHERE s.set_id=?" if set_id is not None else "") + " ORDER BY a.id",
            (set_id,) if set_id is not None else ())
        for a in artifacts:
            try:
                self._set(a["set_id"])
                if a["path"].rsplit("/", 1)[-1] != a["sha256"]:
                    raise ValueError("depth artifact is not stored under its content hash")
                data = local_bytes(self.ctx.campaign.root, a["path"])
                if len(data) != a["bytes"] or _sha(data) != a["sha256"]:
                    raise ValueError("depth artifact hash or length changed")
            except (OSError, ValueError, KeyError) as exc:
                issues.append({"artifact_id": a["id"], "error": str(exc)})
        return {"verified": not issues, "issues": issues, "executed": False}


def report_rows(ctx):
    """Bounded coverage view: candidates, per-context surfaces, open work, coarse conflicts."""
    from .score import applicable_classes, is_inferred_only
    FieldLedger(ctx)  # a fresh campaign may not have run fields sync yet
    ledger = SstiLedger(ctx)
    result, next_cases, candidates, coarse = [], [], [], []
    set_keys = {(r["asset_id"], r["method"], r["location"], r["field"],
                 r["account"], r["role"], r["tenant"], r["workflow"])
                for r in ledger.db.execute(
                    "SELECT asset_id,method,location,field,account,role,tenant,workflow FROM ssti_sets")}
    total_sets = ledger.db.execute("SELECT COUNT(*) FROM ssti_sets").fetchone()[0]
    for r in ledger.db.execute("SELECT id FROM ssti_sets ORDER BY id LIMIT 200").fetchall():
        status = ledger.status(r["id"])
        host = urlsplit(ctx.store.get_asset(status["asset_id"])["value"]).hostname
        for surface in status["surfaces"]:
            result.append([host, status["asset_id"], status["field"], status["account"],
                           status["role"], status["tenant"], status["workflow"], r["id"],
                           surface["surface_id"], surface["kind"],
                           ", ".join(surface["confirmed_families"]) or "-",
                           ", ".join(surface["depth_cases"]) or "-",
                           surface["severity_ceiling"] or "-",
                           len(surface["missing_probes"]), status["integrity"]["verified"]])
            if surface["missing_probes"]:
                next_cases.append([r["id"], surface["surface_id"], surface["kind"],
                                   ", ".join(surface["missing_probes"][:6])])
    for asset in ctx.store.assets("endpoint", in_scope=True)[:1000]:
        if is_inferred_only(asset) or not ctx.scope.is_in(asset["value"]) or \
                "ssti" not in applicable_classes(asset):
            continue
        aid = asset["id"]
        field_rows = ledger.db.execute(
            "SELECT DISTINCT method,location,field,account FROM field_ledger "
            "WHERE asset_id=? AND case_id='ssti-eval' ORDER BY field LIMIT 100", (aid,)).fetchall()
        if not field_rows:
            candidates.append([aid, asset["value"], "no synced SSTI field rows",
                               "run fields sync, then ssti probes"])
        else:
            specific = {(f["field"], f["account"]) for f in field_rows if f["method"]}
            observations = ctx.store.observations(aid)
            for f in field_rows:
                if not f["method"] and (f["field"], f["account"]) in specific:
                    continue
                contexts = ledger._captured_contexts(aid, f["field"], f["method"],
                                                     f["account"], f["location"], observations)
                for role, tenant, workflow in sorted(contexts or {("", "", "")}):
                    key = (aid, f["method"], f["location"], f["field"], f["account"],
                           role, tenant, workflow)
                    if key not in set_keys:
                        candidates.append([aid, asset["value"],
                                           f"{f['method'] or '?'} {f['location']}:{f['field']} "
                                           f"account={f['account'] or '?'} role={role or '?'} "
                                           f"tenant={tenant or '?'} workflow={workflow or '?'}",
                                           "ssti probes for this captured context"])
        row = ledger.db.execute("SELECT status FROM coverage WHERE asset_id=? AND bug_class='ssti'",
                                (aid,)).fetchone()
        if row and row["status"] in ("tested", "confirmed", "refuted", "n-a"):
            open_count = sum(1 for item in result if item[1] == aid and item[-2] > 0)
            missing_count = sum(1 for candidate in candidates if candidate[0] == aid)
            if missing_count or open_count:
                coarse.append([aid, row["status"],
                               f"{missing_count} field gaps; {open_count} open surfaces"])
    return {"surfaces": result[:200], "next": next_cases[:80], "candidates": candidates[:80],
            "coarse": coarse[:80], "limits": {
                "total_sets": total_sets, "audited_sets": min(total_sets, 200),
                "visible_surfaces": min(len(result), 200), "total_audited_surfaces": len(result),
                "visible_candidates": min(len(candidates), 80),
                "total_candidates_in_first_1000_endpoints": len(candidates)}}
