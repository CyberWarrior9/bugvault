"""Offline hostname lifecycle, takeover candidates and operator evidence.

No DNS, browser, provider SDK, network client or claim executor. Records describe
observations, never a code-certified exploit or an automatically promoted finding.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .callbacks import local_bytes, timestamp, valid_marker
from .store import now

MAX_INPUT = 2_000_000
MAX_SCAN = 2000
STAGES = ("precheck", "claimable", "claim", "tls", "chain")
STATES = ("observed", "negative", "blocked", "inconclusive")
CHANNELS = ("owned-lab", "browser", "burp", "native", "scanner")
SCHEMA = """
CREATE TABLE IF NOT EXISTS to_inputs(
 id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE, path TEXT NOT NULL,
 source TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS to_dns(
 id INTEGER PRIMARY KEY, input_id INTEGER NOT NULL REFERENCES to_inputs(id),
 digest TEXT NOT NULL UNIQUE, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS to_sources(
 id INTEGER PRIMARY KEY, kind TEXT NOT NULL, ref TEXT NOT NULL, sha256 TEXT NOT NULL,
 UNIQUE(kind,ref,sha256));
CREATE TABLE IF NOT EXISTS to_sightings(
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, source_id INTEGER NOT NULL REFERENCES to_sources(id),
 seen TEXT NOT NULL, data TEXT NOT NULL, UNIQUE(name,source_id,data));
CREATE TABLE IF NOT EXISTS to_edges(
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, source_id INTEGER NOT NULL
 REFERENCES to_sources(id), data TEXT NOT NULL, UNIQUE(name,kind,source_id,data));
CREATE TABLE IF NOT EXISTS to_candidates(
 id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
 name TEXT NOT NULL, record_type TEXT NOT NULL, value TEXT NOT NULL,
 data TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, updated TEXT NOT NULL,
 UNIQUE(name,record_type,value));
CREATE TABLE IF NOT EXISTS to_events(
 id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES to_candidates(id),
 stage TEXT NOT NULL, state TEXT NOT NULL, snapshot TEXT NOT NULL,
 policy TEXT NOT NULL, data TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS to_cleanup(
 id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES to_events(id),
 outcome TEXT NOT NULL, data TEXT NOT NULL, created TEXT NOT NULL);
"""


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def read_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("takeover input exceeds two megabytes")
    return json.loads(raw)


def capture_receipt(raw, scope=None):
    """Validate labelled response bytes; metadata never supplies the marker proof.

    Minimal receipt: host OR request_url/url, integer status, string body. Prefer
    full request_url for live captures so scheme/port/path exclusions are checked.
    Additional source/capture metadata is retained but not semantically certified.
    """
    try:
        data = json.loads(raw)
        if (not isinstance(data, dict) or type(data.get("status")) is not int
                or not 100 <= data["status"] <= 599 or not isinstance(data.get("body"), str)):
            raise ValueError("capture receipt needs integer status and string response body")
        value = data.get("request_url", data.get("url", data.get("host", "")))
        if not isinstance(value, str):
            raise ValueError("capture receipt needs a hostname or request URL")
        from .takeover_dns import normalize_name
        if "://" in value:
            parsed = urlsplit(value)
            if (parsed.scheme not in ("http", "https") or parsed.username is not None or parsed.password is not None
                    or parsed.fragment or any(c.isspace() for c in value) or "\\" in value):
                raise ValueError("capture receipt requires a plain HTTP(S) request URL")
            host = normalize_name(parsed.hostname)
            if scope is not None and not scope.is_in(value):
                raise ValueError("capture receipt request URL is outside current scope")
        else:
            if scope is not None:
                raise ValueError("live capture receipt requires full request_url")
            host = normalize_name(value)
        return host, data["body"].encode(), data["status"]
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid candidate hostname capture receipt: {exc}") from exc


def validate_config(config):
    if not isinstance(config, dict) or set(config) - {"rules_reviewed", "grants", "budget", "providers"}:
        raise ValueError("takeover config accepts rules_reviewed, grants, budget, providers only")
    grants = config.get("grants", [])
    if (not isinstance(grants, list) or any(g not in ("claim", "chain") for g in grants)
            or len(set(grants)) != len(grants)):
        raise ValueError("takeover.grants must be unique claim/chain grants")
    budget = config.get("budget", 0)
    if type(budget) is not int or not 0 <= budget <= 100_000:
        raise ValueError("takeover.budget must be an integer in 0..100000")
    reviewed = config.get("rules_reviewed", "")
    if reviewed:
        if not isinstance(reviewed, str):
            raise ValueError("takeover.rules_reviewed must be a date")
        day = datetime.strptime(reviewed, "%Y-%m-%d").date()
        if day > datetime.now(timezone.utc).date():
            raise ValueError("takeover rules review cannot be in the future")
    from .takeover_dns import validate_provider_records
    validate_provider_records(config.get("providers", []))
    return config


class TakeoverLedger:
    def __init__(self, ctx):
        self.ctx, self.db = ctx, ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.directory = ctx.campaign.state_dir / "takeover"

    def _keep(self, raw):
        sha = hashlib.sha256(raw).hexdigest()
        path = self.directory / sha
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_bytes() != raw:
            raise ValueError("takeover evidence copy was altered")
        if not path.exists():
            path.write_bytes(raw)
        return {"path": str(path.relative_to(self.ctx.campaign.root)), "sha256": sha,
                "bytes": len(raw)}

    def _source(self, kind, ref, value):
        sha = digest(value)
        self.db.execute("INSERT OR IGNORE INTO to_sources(kind,ref,sha256) VALUES(?,?,?)",
                        (kind, str(ref), sha))
        return self.db.execute("SELECT id FROM to_sources WHERE kind=? AND ref=? AND sha256=?",
                               (kind, str(ref), sha)).fetchone()[0]

    def _sighting(self, name, source, seen, data=None):
        self.db.execute("INSERT OR IGNORE INTO to_sightings(name,source_id,seen,data) VALUES(?,?,?,?)",
                        (name, source, seen, encoded(data or {})))

    def import_capture(self, data):
        from .takeover_dns import MAX_OBSERVATIONS, validate_capture
        clean = validate_capture(data)
        present = {r[0] for r in self.db.execute("SELECT digest FROM to_dns")}
        if len(present | {digest(o) for o in clean["observations"]}) > MAX_OBSERVATIONS:
            raise ValueError("takeover campaign DNS history exceeds 2000 unique observations; use a bounded campaign")
        kept = self._keep(encoded(clean).encode())
        self.db.execute("INSERT OR IGNORE INTO to_inputs(sha256,path,source,created) VALUES(?,?,?,?)",
                        (kept["sha256"], kept["path"], clean["source"], now()))
        iid = self.db.execute("SELECT id FROM to_inputs WHERE sha256=?", (kept["sha256"],)).fetchone()[0]
        source = self._source("input", iid, clean)
        for observation in clean["observations"]:
            self.db.execute("INSERT OR IGNORE INTO to_dns(input_id,digest,data) VALUES(?,?,?)",
                            (iid, digest(observation), encoded(observation)))
            self._sighting(observation["name"], source, observation["observed_at"],
                           {k: observation[k] for k in ("record_type", "result", "vantage",
                            "certificate_not_before", "certificate_not_after") if k in observation})
        self.db.commit()
        result = self.sync()
        return {**result, "input_id": iid, "observations": len(clean["observations"])}

    def _response(self, rid):
        response = self.ctx.store.response(rid)
        body = b""
        if response["body_sha256"]:
            path = self.ctx.store.bodies_dir / response["body_sha256"]
            if not path.is_file() or path.stat().st_size > 5_000_000:
                raise ValueError("missing or oversized stored response body")
            body = path.read_bytes()
            if hashlib.sha256(body).hexdigest() != response["body_sha256"]:
                raise ValueError("stored response body hash mismatch")
        return response, body

    def sync(self):
        from .takeover_dns import classify, normalize_name
        from .takeover_trust import extract_trust
        gaps = []
        assets = self.ctx.store.assets()
        self.db.execute("UPDATE to_candidates SET active=0")
        archive_sources = {a["attrs"].get("archive_request_id"): a for a in assets[:MAX_SCAN]
                           if a["attrs"].get("archive_request_id") and self.ctx.scope.is_in(a["value"])}
        for asset in assets[:MAX_SCAN]:
            try:
                raw_name = asset.get("host") or asset["value"]
                name = normalize_name(urlsplit(raw_name).hostname if "://" in raw_name else raw_name)
            except ValueError:
                continue
            source = self._source("asset", asset["id"], asset)
            self._sighting(name, source, asset["last_seen"],
                           {"sources": asset["attrs"].get("sources", []),
                            "first_seen": asset["first_seen"], "last_seen": asset["last_seen"],
                            "certificates": asset["attrs"].get("ct_certificates", []),
                            "archive_last": asset["attrs"].get("archive_last", ""),
                            "status": asset["attrs"].get("status", asset["attrs"].get("reported_status"))})
            # Legacy probe evidence is a heuristic snapshot, not a typed DNS capture.
            if asset["kind"] == "host" and asset["attrs"].get("cname"):
                cname = asset["attrs"]["cname"]
                if asset["attrs"].get("resolves") is False:
                    self._candidate({"name": name, "record_type": "CNAME", "value": cname,
                                     "provider": "", "confidence": "candidate",
                                     "basis": ["legacy probe: missing address reason unclassified"],
                                     "legacy_source": source})
        rows = self.db.execute("SELECT id FROM requests WHERE status IS NOT NULL AND error IS NULL "
                               "ORDER BY id DESC LIMIT ?", (MAX_SCAN,)).fetchall()
        for row in rows:
            try:
                response, body = self._response(row["id"])
                # An archive response needs an explicit previously captured asset
                # association. Never reinterpret arbitrary third-party responses.
                archived = archive_sources.get(row["id"])
                origin_url = archived["value"] if archived else response["url"]
                if not self.ctx.scope.is_in(origin_url):
                    continue
                source = self._source("response", row["id"], response)
                setter = normalize_name(urlsplit(origin_url).hostname or "")
                self._sighting(setter, source, response["ts"],
                               {"status": response["status"], "basis": response["basis"], "historical": bool(archived)})
                for edge in extract_trust(origin_url, {} if archived else response["resp_headers"],
                                          body.decode("utf-8", "replace"),
                                          complete=response["body_complete"] == 1):
                    edge["details"]["historical"] = bool(archived)
                    edge["details"]["captured_at"] = response["ts"]
                    edge["details"]["capture_basis"] = response["basis"]
                    name = edge["name"]
                    self.db.execute("INSERT OR IGNORE INTO to_edges(name,kind,source_id,data) VALUES(?,?,?,?)",
                                    (name, edge["kind"], source, encoded(edge)))
                    self._sighting(name, source, response["ts"], {"kind": edge["kind"]})
            except (ValueError, KeyError, OSError) as exc:
                gaps.append({"response": row["id"], "reason": str(exc)})
        observations, reference_inputs, input_sources = [], {}, {}
        for row in self.db.execute("SELECT input_id,data FROM to_dns"):
            observation = json.loads(row["data"])
            observations.append(observation)
            key = (observation["name"], observation["record_type"], observation["value"])
            reference_inputs.setdefault(key, set()).add(row["input_id"])
        providers = self.ctx.campaign.raw.get("takeover", {}).get("providers", [])
        # Preserve old candidates as inactive history; only current qualifying
        # legacy conditions or the latest typed observations reactivate a row.
        for candidate in classify(observations, provider_status=providers):
            # Reverse mail/DKIM dependencies are provenance-backed reference
            # edges, never authenticated-mail control or permission to probe.
            for dependency in candidate.get("dependencies", []):
                name = dependency["name"]
                key = (candidate["name"], candidate["record_type"], candidate["value"])
                for iid in reference_inputs.get(key, set()):
                    if iid not in input_sources:
                        item = self.db.execute("SELECT path FROM to_inputs WHERE id=?", (iid,)).fetchone()
                        source_data = json.loads(local_bytes(self.ctx.campaign.root, item["path"]))
                        input_sources[iid] = self._source("input", iid, source_data)
                    source = input_sources[iid]
                    edge = {"name": name, "kind": dependency["kind"], "conditional": True,
                            "reference": candidate["name"], "details": dependency}
                    self.db.execute("INSERT OR IGNORE INTO to_edges(name,kind,source_id,data) VALUES(?,?,?,?)",
                                    (name, edge["kind"], source, encoded(edge)))
                    self._sighting(name, source, candidate["observed_at"], {"kind": dependency["kind"]})
            if candidate["record_type"] in ("A", "AAAA", "SOA"):
                # Stored DNS evidence is not a claimability signal for a recycled
                # address pool, nor is a normal SOA a takeover candidate.
                continue
            if candidate["record_type"] in ("MX", "TXT") and not candidate.get("dependencies"):
                continue
            self._candidate(candidate)
        self.db.commit()
        return {"executed": False, "candidates": self.db.execute("SELECT count(*) FROM to_candidates").fetchone()[0],
                "gaps": gaps, "scan_limit": MAX_SCAN, "inventory_complete": False}

    def _candidate(self, candidate):
        name = candidate["name"]
        if not self.ctx.scope.host_in(name):
            return
        existing = self.ctx.store.find_asset("host", name)
        asset = existing["id"] if existing else self.ctx.store.upsert_asset(
            "host", name, host=name, in_scope=True, attrs={"sources": ["takeover-offline"]})[0]
        self.db.execute("INSERT INTO to_candidates(asset_id,name,record_type,value,data,updated) "
                        "VALUES(?,?,?,?,?,?) ON CONFLICT(name,record_type,value) DO UPDATE SET "
                        "data=excluded.data,active=1,updated=excluded.updated",
                        (asset, name, candidate["record_type"], candidate["value"], encoded(candidate), now()))
        self.ctx.store.seed_coverage(asset, {"subdomain-takeover": "DNS/provider lead; claimability and impact unverified"})

    def _edges(self, name):
        from .takeover_trust import host_matches
        edges = []
        for row in self.db.execute("SELECT e.*,s.kind AS source_kind,s.ref,s.sha256 FROM to_edges e "
                                   "JOIN to_sources s ON s.id=e.source_id ORDER BY e.id DESC LIMIT 10000"):
            edge = json.loads(row["data"])
            matched = host_matches(name, row["name"])
            if row["kind"] == "cookie-domain":
                matched = name == row["name"] or name.endswith("." + row["name"])
            elif row["kind"] == "hsts":
                details = edge.get("details", {})
                matched = name == row["name"] or (name.endswith("." + row["name"]) and
                    details.get("include_subdomains") and details.get("secure_setter") and details.get("max_age", 0) > 0)
            if matched:
                edges.append({**edge, "source_id": row["source_id"], "source_kind": row["source_kind"],
                              "source_ref": row["ref"], "source_sha256": row["sha256"]})
        return edges

    def _get(self, cid):
        row = self.db.execute("SELECT * FROM to_candidates WHERE id=?", (cid,)).fetchone()
        if not row:
            raise ValueError("unknown takeover candidate")
        if not self.ctx.scope.host_in(row["name"]):
            raise ValueError("takeover candidate is no longer in scope")
        data = json.loads(row["data"])
        if any(row[key] != data.get(key) for key in ("name", "record_type", "value")):
            raise ValueError("takeover candidate identity differs from its captured data")
        asset = self.ctx.store.get_asset(row["asset_id"])
        if asset["kind"] != "host" or asset["value"] != row["name"]:
            raise ValueError("takeover candidate asset binding changed")
        return {**dict(row), "data": data}

    def _snapshot(self, cid):
        c = self._get(cid)
        # Bind only this candidate and its literal dependencies/controls/referrals,
        # not every unrelated observation elsewhere in the campaign.
        related = {c["name"]}
        if c["record_type"] in ("CNAME", "NS") and c["value"]:
            related.add(c["value"])
        related.update(d["name"] for d in c["data"].get("dependencies", []))
        dns = []
        for row in self.db.execute("SELECT digest,data FROM to_dns ORDER BY digest"):
            observation = json.loads(row["data"])
            if (observation["name"] in related or observation.get("control_for") in related
                    or observation.get("control_for") == c["name"].partition(".")[2]):
                dns.append(row["digest"])
        identity = {key: c[key] for key in ("id", "asset_id", "name", "record_type", "value", "active")}
        return digest({"identity": identity, "candidate": c["data"], "dns": dns, "edges": self._edges(c["name"]),
                       "providers": self.ctx.campaign.raw.get("takeover", {}).get("providers", [])})

    def _policy(self):
        raw = self.ctx.campaign.raw
        return digest({k: raw.get(k) for k in ("takeover", "program_url", "rules", "in_scope",
                                              "out_of_scope", "excluded_bug_classes", "policy")})

    def _fresh_problem(self, candidate):
        from .takeover_dns import provider_info
        observed = candidate["data"].get("observed_at")
        if not observed or not 0 <= timestamp(now()) - timestamp(observed) <= 86400:
            return "live claim evidence requires a DNS capture from the last 24 hours"
        if candidate["data"].get("wildcard_state") != "negative":
            return "wildcard controls are missing, ambiguous or matching; live claim evidence blocked"
        if (candidate["record_type"] == "NS" and
                candidate["data"].get("referral_state") not in ("match", "mismatch")):
            return "NS claim evidence requires parent/child referral context"
        info = provider_info(candidate["data"].get("provider"),
                             self.ctx.campaign.raw.get("takeover", {}).get("providers", []))
        if info.get("stale", True) or info.get("status") != "vulnerable":
            return "provider status is stale, patched or unknown/edge-case; review before live claim evidence"
        return ""

    def show(self, cid):
        candidate = self._get(cid)
        edges = self._edges(candidate["name"])
        weight = {"oauth-redirect": 6, "csp-script": 5, "cors": 5, "cookie-domain": 4,
                  "content-reference": 2, "hsts": 0}
        score = sum(weight.get(k, 1) for k in {e["kind"] for e in edges
                                              if not e.get("details", {}).get("historical")})
        if any(e.get("details", {}).get("historical") for e in edges):
            score += 1  # Historical references do not have current production trust weight.
        events = [dict(r) for r in self.db.execute("SELECT * FROM to_events WHERE candidate_id=? ORDER BY id", (cid,))]
        current = self._snapshot(cid)
        for event in events:
            event["data"] = json.loads(event["data"])
            event["stale"] = event["snapshot"] != current or event["policy"] != self._policy()
            if event["data"].get("channel") != "owned-lab" and event["stage"] != "precheck":
                event["freshness_problem"] = self._fresh_problem(candidate)
                event["stale"] |= bool(event["freshness_problem"])
        lifecycle = [dict(r) for r in self.db.execute(
            "SELECT s.*,p.kind AS source_kind,p.ref AS source_ref,p.sha256 AS source_sha256 "
            "FROM to_sightings s JOIN to_sources p ON p.id=s.source_id WHERE name=? ORDER BY seen,id LIMIT 200",
            (candidate["name"],))]
        for sighting in lifecycle:
            sighting["data"] = json.loads(sighting["data"])
        cards = []
        for stage in STAGES:
            latest = next((e for e in reversed(events) if e["stage"] == stage), None)
            cards.append({"stage": stage, "state": latest["state"] if latest else "untested",
                          "stale": latest["stale"] if latest else False})
        return {**candidate, "trust_edges": edges, "priority": score, "events": events,
                "lifecycle": lifecycle, "stages": cards,
                "snapshot": current, "executed": False, "impact": "conditional; not demonstrated",
                "dossier_required": ["provider status/source/date", "namespace availability and verification rules",
                                     "owned account/resource", "written claim permission", "before/after/control",
                                     "TLS/browser evidence if needed", "cleanup owner/deadline/receipt", "chain proof"]}

    def plan(self, limit=25):
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("takeover limit must be 1..200")
        candidates = [self.show(r["id"]) for r in self.db.execute("SELECT id,name FROM to_candidates")
                      if self.ctx.scope.host_in(r["name"])]
        candidates.sort(key=lambda c: (-c["priority"], c["id"]))
        return {"executed": False, "inventory_complete": False, "total": len(candidates),
                "candidates": candidates[:limit], "basis": "priority is conditional trust, not severity or claimability"}

    def _current_event(self, cid, stage):
        row = self.db.execute("SELECT * FROM to_events WHERE candidate_id=? AND stage=? "
                              "ORDER BY id DESC LIMIT 1", (cid, stage)).fetchone()
        return bool(row and row["state"] == "observed" and row["snapshot"] == self._snapshot(cid)
                    and row["policy"] == self._policy() and
                    (stage == "precheck" or json.loads(row["data"]).get("channel") == "owned-lab"
                     or not self._fresh_problem(self._get(cid))))

    def record(self, data):
        allowed = {"schema", "candidate", "stage", "state", "note", "channel", "requests", "marker",
                   "control_marker", "artifacts", "account", "resource", "cleanup_owner", "cleanup_due"}
        if (not isinstance(data, dict) or type(data.get("schema")) is not int
                or data.get("schema") != 1 or set(data) - allowed):
            raise ValueError("invalid schema-1 takeover event")
        cid, stage, state = data.get("candidate"), data.get("stage"), data.get("state")
        if type(cid) is not int or stage not in STAGES or state not in STATES:
            raise ValueError("invalid takeover candidate/stage/state")
        candidate = self._get(cid)
        note = data.get("note", "")
        if not isinstance(note, str) or not 1 <= len(note) <= 2000:
            raise ValueError("takeover event needs a bounded note")
        channel = data.get("channel", "owned-lab")
        if channel not in CHANNELS:
            raise ValueError("invalid takeover evidence channel")
        requests = data.get("requests", 0)
        if type(requests) is not int or not 0 <= requests <= 10000:
            raise ValueError("takeover requests must be 0..10000")
        artifacts = data.get("artifacts", {})
        if (not isinstance(artifacts, dict) or len(artifacts) > 10 or
                any(not isinstance(k, str) or not isinstance(v, str) for k, v in artifacts.items())):
            raise ValueError("takeover artifacts must map at most ten roles to paths")
        live = channel != "owned-lab"
        config = validate_config(self.ctx.campaign.raw.get("takeover", {}))
        if live and state == "observed":
            if "subdomain-takeover" in self.ctx.campaign.raw.get("excluded_bug_classes", []):
                raise ValueError("subdomain-takeover is an excluded bug class")
            for pending in self._cleanup_open():
                receipt = self.db.execute("SELECT outcome FROM to_cleanup WHERE event_id=? ORDER BY id DESC LIMIT 1",
                                          (pending["event"],)).fetchone()
                if pending["overdue"] or receipt and receipt["outcome"] == "failed":
                    raise ValueError("failed or overdue cleanup blocks further live success evidence")
        if live and state not in ("blocked", "inconclusive"):
            if (not self.ctx.campaign.raw.get("program_url") or not config.get("rules_reviewed")
                    or not self.ctx.campaign.raw.get("rules") or not self.ctx.policy.allows("active")):
                raise ValueError("live takeover evidence needs program URL, reviewed rules and active policy")
            grant = "chain" if stage == "chain" else "claim"
            if grant not in config.get("grants", []):
                raise ValueError("missing takeover evidence grant")
            used = sum(json.loads(r["data"]).get("requests", 0) for r in self.db.execute("SELECT data FROM to_events")
                       if json.loads(r["data"]).get("channel") != "owned-lab")
            if requests < 1 or used + requests > config.get("budget", 0):
                raise ValueError("takeover declared shared budget exhausted or missing")
        # Read once. Validation and content-addressed storage use these exact
        # immutable bytes, even if the operator's source path later changes.
        raw_artifacts = {role: local_bytes(self.ctx.campaign.root, path) for role, path in artifacts.items()}
        if state == "observed":
            if not candidate["active"]:
                raise ValueError("candidate is historical/inactive; obtain current evidence first")
            if not self.verify()["ok"]:
                raise ValueError("takeover evidence integrity failed; preserve and resolve before recording success")
            required = {"precheck": {"review"}, "claimable": {"provider", "namespace", "control"},
                        "claim": {"permission", "ownership", "before", "after", "control", "cleanup_plan"},
                        "tls": {"tls", "control"}, "chain": {"replay", "control", "impact"}}[stage]
            if not required <= set(artifacts):
                raise ValueError(f"{stage} evidence requires roles {sorted(required)}")
            if stage != "precheck" and not self._current_event(cid, "precheck"):
                raise ValueError("current precheck is required before claimability/claim/chain")
            if stage in ("claim", "tls", "chain"):
                if stage == "claim" and not self._current_event(cid, "claimable"):
                    raise ValueError("current claimability evidence is required before claim")
                if stage != "claim" and not self._current_event(cid, "claim"):
                    raise ValueError("current claim marker evidence is required")
            if live and stage != "precheck":
                problem = self._fresh_problem(candidate)
                if problem:
                    raise ValueError(problem)
            if stage == "claim":
                for pending in self._cleanup_open():
                    other = self.db.execute("SELECT name FROM to_candidates WHERE id=?", (pending["candidate"],)).fetchone()
                    if other and other["name"] == candidate["name"]:
                        raise ValueError("unresolved cleanup blocks another claim on this candidate")
                for key in ("account", "resource", "cleanup_owner", "cleanup_due"):
                    if not isinstance(data.get(key), str) or not 1 <= len(data[key].strip()) <= 300:
                        raise ValueError(f"claim needs {key}")
                if timestamp(data["cleanup_due"]) <= timestamp(now()):
                    raise ValueError("cleanup deadline must be in the future")
            if stage in ("claim", "chain"):
                marker, control = data.get("marker"), data.get("control_marker")
                if not valid_marker(marker) or not valid_marker(control) or marker == control:
                    raise ValueError("distinct valid attempt/control markers are required")
                test = raw_artifacts["after" if stage == "claim" else "replay"]
                negative = raw_artifacts["control"]
                if stage == "claim":
                    host, test_body, status = capture_receipt(test, self.ctx.scope if live else None)
                    _, negative_body, _ = capture_receipt(negative, self.ctx.scope if live else None)
                    if host != candidate["name"] or not 200 <= status < 300:
                        raise ValueError("successful candidate hostname receipt is required")
                    test, negative = test_body, negative_body
                if marker.encode() not in test or marker.encode() in negative or control.encode() not in negative:
                    raise ValueError("marker/control round trip failed")
                if control.encode() in test:
                    raise ValueError("positive response also contains the negative-control marker")
                if stage == "claim":
                    for previous in self.db.execute("SELECT data FROM to_events WHERE stage='claim' AND state='observed'"):
                        if json.loads(previous["data"]).get("marker") == marker:
                            raise ValueError("claim attempt marker was already used; mint a fresh marker")
                    before_host, before_body, _ = capture_receipt(raw_artifacts["before"], self.ctx.scope if live else None)
                    if marker.encode() in before_body:
                        raise ValueError("claim marker already present in before control")
                    if before_host != candidate["name"]:
                        raise ValueError("before receipt must be bound to the candidate hostname")
        # All successful validation happens before an event or budget is written.
        kept = {role: self._keep(raw) for role, raw in raw_artifacts.items()}
        if "control" in kept and state == "observed":
            positive = "after" if stage == "claim" else "replay" if stage == "chain" else "namespace" if stage == "claimable" else "tls"
            if positive in kept and kept[positive]["sha256"] == kept["control"]["sha256"]:
                raise ValueError("positive evidence and negative control must be distinct")
        saved = {**data, "channel": channel, "requests": requests, "artifacts": kept}
        cur = self.db.execute("INSERT INTO to_events(candidate_id,stage,state,snapshot,policy,data,created) "
                              "VALUES(?,?,?,?,?,?,?)", (cid, stage, state, self._snapshot(cid),
                                                       self._policy(), encoded(saved), now()))
        self.db.commit()
        return {"event_id": cur.lastrowid, "executed": False, "finding_promoted": False,
                "assessment": "operator evidence recorded; validator must judge meaning"}

    def cleanup(self, data):
        if (not isinstance(data, dict) or set(data) != {"schema", "event", "outcome", "artifact", "note"}
                or type(data["schema"]) is not int or data["schema"] != 1
                or type(data["event"]) is not int or not isinstance(data["artifact"], str)
                or not isinstance(data["note"], str) or not 1 <= len(data["note"]) <= 2000
                or data["outcome"] not in ("released", "deleted", "retained-approved", "failed")):
            raise ValueError("invalid takeover cleanup schema")
        event = self.db.execute("SELECT * FROM to_events WHERE id=?", (data["event"],)).fetchone()
        if not event or event["stage"] != "claim" or event["state"] != "observed":
            raise ValueError("cleanup needs an observed claim event")
        # Keep cleanup evidence even after scope is narrowed: this records a
        # receipt and does not authorize or execute any external cleanup action.
        raw_receipt = local_bytes(self.ctx.campaign.root, data["artifact"])
        # Structured equality, not a prefix match such as owned-1 vs owned-10.
        claim = json.loads(event["data"])
        try:
            receipt = json.loads(raw_receipt)
        except ValueError as exc:
            raise ValueError("cleanup receipt must be JSON bound to the claimed resource") from exc
        if not isinstance(receipt, dict) or receipt.get("resource") != claim["resource"]:
            raise ValueError("cleanup receipt must bind the claimed resource")
        ref = self._keep(raw_receipt)
        saved = {**data, "artifact": ref}
        self.db.execute("INSERT INTO to_cleanup(event_id,outcome,data,created) VALUES(?,?,?,?)",
                        (event["id"], data["outcome"], encoded(saved), now()))
        self.db.commit()
        return {"executed": False, "outcome": data["outcome"], "receipt": ref}

    def verify(self):
        errors = []
        inputs, observation_digests = {}, {}
        def check(ref, label):
            try:
                raw = local_bytes(self.ctx.campaign.root, ref["path"])
                if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
                    raise ValueError("hash mismatch")
            except (ValueError, OSError) as exc:
                errors.append({"ref": label, "reason": str(exc)})
        for row in self.db.execute("SELECT * FROM to_inputs"):
            try:
                raw = local_bytes(self.ctx.campaign.root, row["path"])
                if hashlib.sha256(raw).hexdigest() != row["sha256"]:
                    raise ValueError("hash mismatch")
                data = json.loads(raw)
                inputs[row["id"]] = data
                observation_digests[row["id"]] = {digest(o) for o in data["observations"]}
            except (ValueError, KeyError, OSError, TypeError) as exc:
                errors.append({"ref": f"input:{row['id']}", "reason": str(exc)})
        for row in self.db.execute("SELECT * FROM to_dns"):
            try:
                data = json.loads(row["data"])
                if digest(data) != row["digest"] or row["digest"] not in observation_digests.get(row["input_id"], set()):
                    raise ValueError("DNS observation differs from its captured source")
            except (ValueError, KeyError, OSError, TypeError) as exc:
                errors.append({"ref": f"dns:{row['id']}", "reason": str(exc)})
        for row in self.db.execute("SELECT * FROM to_sources"):
            try:
                if row["kind"] == "response":
                    value, _ = self._response(int(row["ref"]))
                elif row["kind"] == "asset":
                    # Asset evolution is normal; it stays an historical sighting.
                    continue
                else:
                    value = inputs[int(row["ref"])]
                if digest(value) != row["sha256"]:
                    raise ValueError("source snapshot changed")
            except (ValueError, KeyError, OSError, TypeError) as exc:
                errors.append({"ref": f"source:{row['id']}", "reason": str(exc)})
        for row in self.db.execute("SELECT * FROM to_candidates"):
            try:
                data = json.loads(row["data"])
                asset = self.ctx.store.get_asset(row["asset_id"])
                if (any(row[key] != data.get(key) for key in ("name", "record_type", "value"))
                        or asset["kind"] != "host" or asset["value"] != row["name"]):
                    raise ValueError("candidate identity/asset differs from captured data")
            except (ValueError, KeyError, TypeError) as exc:
                errors.append({"ref": f"candidate:{row['id']}", "reason": str(exc)})
        for table in ("to_events", "to_cleanup"):
            for row in self.db.execute(f"SELECT id,data FROM {table}"):
                data = json.loads(row["data"])
                refs = data.get("artifacts", {}) if table == "to_events" else {"cleanup": data["artifact"]}
                for role, ref in refs.items():
                    check(ref, f"{table}:{row['id']}:{role}")
        return {"ok": not errors, "errors": errors, "executed": False}

    def _cleanup_open(self):
        unresolved = []
        for row in self.db.execute("SELECT * FROM to_events WHERE stage='claim' AND state='observed'"):
            receipt = self.db.execute("SELECT outcome FROM to_cleanup WHERE event_id=? ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
            if not receipt or receipt["outcome"] == "failed":
                data = json.loads(row["data"])
                unresolved.append({"event": row["id"], "candidate": row["candidate_id"],
                                   "owner": data["cleanup_owner"], "due": data["cleanup_due"],
                                   "overdue": timestamp(data["cleanup_due"]) < timestamp(now())})
        return unresolved

    def status(self, limit=25):
        unresolved = self._cleanup_open()
        hosts = []
        for row in self.db.execute("SELECT name,min(seen) AS first_seen,max(seen) AS last_seen,"
                                   "count(*) AS observations FROM to_sightings GROUP BY name ORDER BY name LIMIT ?", (limit,)):
            hosts.append({**dict(row), "in_scope": self.ctx.scope.host_in(row["name"]),
                          "reference_kinds": sorted({e["kind"] for e in self._edges(row["name"])})})
        return {**self.plan(limit), "integrity": self.verify(), "cleanup_open": unresolved,
                "hosts": hosts,
                "sightings": self.db.execute("SELECT count(*) FROM to_sightings").fetchone()[0],
                "out_of_scope": sorted({r["name"] for r in self.db.execute("SELECT DISTINCT name FROM to_sightings")
                                        if not r["name"].startswith("*.") and not self.ctx.scope.host_in(r["name"])}),
                "coverage_complete": False}
