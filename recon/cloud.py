"""Offline cloud-reference and exact-operation evidence ledger (partial M1–M3).

Does not call cloud APIs, validate credentials, claim names, send requests,
certify IAM, perform impact actions, or promote findings. Live-labelled receipts
are operator-supplied assertions and their declared budget is NOT an executor.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from .callbacks import local_bytes, valid_marker
from .campaign import HTTP_METHODS
from .cloud_refs import MAX_TEXT, cloud_references
from .extract import SECRET_PATTERNS
from .store import now

FAMILIES = tuple("CM-%02d" % i for i in range(19))
STATES = ("blocked", "inconclusive", "negative", "observed", "canary-proved")
CHANNELS = ("offline", "owned-lab", "native", "burp")
GRANTS = frozenset({"read", "write", "discovery", "chain", "impact", "burst"})
ROLES = frozenset({"owner-baseline", "low-baseline", "test", "replay", "negative-control",
                   "legitimate-control", "before", "after", "cleanup", "identity", "audit"})
CONTENT = frozenset({"public-asset", "source", "config", "backup", "pii",
                      "credential-looking", "synthetic", "unknown"})
PUBLICNESS = frozenset({"public-intended", "private", "unknown"})
OBJECTIVES = frozenset({"read", "mutate", "persist", "audit-evade", "destroy-assess"})
_LABEL = re.compile(r"^[A-Za-z0-9_.:/@+-]{1,200}$")
SCHEMA = """
CREATE TABLE IF NOT EXISTS cloud_sources(
  id INTEGER PRIMARY KEY, source_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
  ref TEXT NOT NULL, sha256 TEXT NOT NULL, snapshot TEXT NOT NULL,
  media_type TEXT NOT NULL, historical INTEGER NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cloud_refs(
  id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL REFERENCES cloud_sources(id),
  provider TEXT NOT NULL, resource_kind TEXT NOT NULL, native_identifier TEXT NOT NULL,
  scope TEXT NOT NULL, start INTEGER NOT NULL, end INTEGER NOT NULL,
  signed INTEGER NOT NULL, score INTEGER NOT NULL, signals TEXT NOT NULL,
  UNIQUE(source_id, provider, resource_kind, native_identifier, start, end));
CREATE TABLE IF NOT EXISTS cloud_events(
  id INTEGER PRIMARY KEY, ref_id INTEGER NOT NULL REFERENCES cloud_refs(id),
  family TEXT NOT NULL, state TEXT NOT NULL, channel TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE, policy_hash TEXT NOT NULL,
  data TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cloud_generated(
  id INTEGER PRIMARY KEY, spec_path TEXT NOT NULL, spec_sha256 TEXT NOT NULL,
  policy_hash TEXT NOT NULL, url TEXT NOT NULL, created TEXT NOT NULL,
  UNIQUE(spec_sha256,url));
"""
_WORD = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
_SHARED_PROVIDER = (".amazonaws.com", ".amazonaws.com.cn", ".googleapis.com",
                    ".blob.core.windows.net", ".cloudfunctions.net")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_TEXT + 1)
    if len(raw) > MAX_TEXT:
        raise ValueError("cloud input exceeds two megabytes")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("cloud event must be a JSON object")
    return data


def _local(root, relative):
    """Read within campaign, refusing symlinks even when they resolve inside it."""
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("cloud evidence needs a campaign-relative file")
    base = Path(root).resolve()
    path = base / relative
    if any(part in ("..", "") for part in Path(relative).parts):
        raise ValueError("cloud evidence path escapes campaign")
    for component in (path, *path.parents):
        if component == base:
            break
        if component.is_symlink():
            raise ValueError("cloud evidence symlinks are not accepted")
    return local_bytes(base, relative)


def _only(data, allowed, label):
    if not isinstance(data, dict) or set(data) - set(allowed):
        raise ValueError(f"{label} requires an object with known keys")


def _label(value, label):
    if (not isinstance(value, str) or not _LABEL.fullmatch(value) or
            any(secret.search(value) for secret in SECRET_PATTERNS.values())):
        raise ValueError(f"{label} must be a bounded, value-free label")
    return value


def _policy(ctx):
    return sha(canonical({"program_url": ctx.campaign.raw.get("program_url", ""),
                          "rules": ctx.campaign.raw.get("rules", []),
                          "in_scope": ctx.campaign.raw.get("in_scope", []),
                          "out_of_scope": ctx.campaign.raw.get("out_of_scope", []),
                          "policy": ctx.campaign.raw.get("policy", {}),
                          "cloud": ctx.campaign.raw.get("cloud", {})}).encode())


class CloudLedger:
    def __init__(self, ctx):
        self.ctx, self.db = ctx, ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()

    def _seed_response_coverage(self, request_id):
        from .extract import origin_of
        response = self.ctx.store.response(int(request_id))
        for asset_kind, value in (("js", response["url"]),
                                  ("sourcemap", response["url"]),
                                  ("service", origin_of(response["url"]))):
            asset = self.ctx.store.find_asset(asset_kind, value)
            if asset and asset["in_scope"]:
                self.ctx.store.seed_coverage(asset["id"], {"cloud-misconfiguration":
                    "cloud reference in stored source; resource ownership and policy unverified"})
                break

    def _register(self, kind, ref, raw, media_type, *, historical=False, snapshot=None):
        if not isinstance(raw, bytes) or len(raw) > MAX_TEXT:
            raise ValueError("cloud source exceeds two megabytes")
        # Refuse lossy decoding: selector spans and SHA-256 must bind the same
        # source text, not a replacement-character derivative.
        text = raw.decode("utf-8")
        source_key = sha((kind + "\0" + ref + "\0" + sha(raw)).encode())
        parsed = cloud_references(text, source_ref="source:" + source_key[:24],
                                  media_type=media_type, historical=historical)
        row = self.db.execute("SELECT id FROM cloud_sources WHERE source_key=?", (source_key,)).fetchone()
        if row:
            if kind == "response" and parsed:
                self._seed_response_coverage(ref)
            return {"source": row[0], "references": len(parsed), "new": False}
        with self.db:
            cur = self.db.execute("INSERT INTO cloud_sources(source_key,kind,ref,sha256,snapshot,"
                                  "media_type,historical,created) VALUES(?,?,?,?,?,?,?,?)",
                                  (source_key, kind, ref, sha(raw), canonical(snapshot or {}),
                                   media_type, int(historical), now()))
            for item in parsed:
                self.db.execute("INSERT INTO cloud_refs(source_id,provider,resource_kind,"
                                "native_identifier,scope,start,end,signed,score,signals) "
                                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                                (cur.lastrowid, item["provider"], item["resource_kind"],
                                 item["native_identifier"], canonical(item["scope"]),
                                 item["selector"]["start"], item["selector"]["end"],
                                 int(item["signed_context"]), item["probe_priority"],
                                 canonical(item["triage_signals"])))
        if kind == "response" and parsed:
            self._seed_response_coverage(ref)
        return {"source": cur.lastrowid, "references": len(parsed), "new": True}

    def import_text(self, relative, media_type="text/plain", historical=False):
        _label(media_type, "media_type")
        raw = _local(self.ctx.campaign.root, relative)
        return {**self._register("file", relative, raw, media_type, historical=historical),
                "executed": False}

    def generate_file(self, relative):
        """OFFLINE R5 hostname proposals only; never a probe list or claim.

        The current URL scope model cannot grant provider-global namespaces.
        Those are deliberately refused rather than treating a website wildcard
        as authority over unrelated accounts at a shared provider.
        """
        raw = _local(self.ctx.campaign.root, relative)
        if len(raw) > MAX_TEXT:
            raise ValueError("cloud generation spec exceeds two megabytes")
        spec = json.loads(raw)
        _only(spec, {"schema", "pattern", "words"}, "cloud generation spec")
        cfg = self.ctx.campaign.raw.get("cloud", {})
        if ("discovery" not in cfg.get("grants", []) or not cfg.get("rules_reviewed") or
                not cfg.get("budget") or not self.ctx.campaign.raw.get("program_url") or
                not self.ctx.campaign.raw.get("rules") or self.ctx.policy.mode != "loud"):
            raise ValueError("hostname proposals need a reviewed discovery label, written "
                             "rules, positive budget and loud mode; no traffic is sent")
        pattern, words = spec.get("pattern"), spec.get("words")
        if (spec.get("schema") != 1 or not isinstance(pattern, str) or
                pattern.count("{word}") != 1 or len(pattern) > 300 or
                not isinstance(words, list) or not 1 <= len(words) <= 100 or
                any(not isinstance(w, str) or not _WORD.fullmatch(w) for w in words) or
                len(set(words)) != len(words) or len(words) > cfg["budget"]):
            raise ValueError("generation needs schema=1, one hostname placeholder and "
                             "1..100 distinct source words within the declared budget")
        sample = pattern.replace("{word}", "bvfixture")
        parsed = urlsplit(sample)
        if (parsed.scheme not in ("https", "http") or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                parsed.query or parsed.fragment or parsed.path not in ("", "/") or
                any(c.isspace() for c in sample) or
                "{word}" not in urlsplit(pattern).netloc or
                any(parsed.hostname.endswith(suffix) for suffix in _SHARED_PROVIDER)):
            raise ValueError("only plain hostname patterns on non-shared program origins are supported")
        if not any(rule.suffix and parsed.hostname.endswith("." + rule.suffix)
                   for rule in self.ctx.scope.include):
            raise ValueError("generation needs an explicit wildcard in campaign scope")
        candidates = [pattern.replace("{word}", word) for word in sorted(words)]
        if not all(self.ctx.scope.is_in(url) for url in candidates):
            raise ValueError("generated hostname falls outside an allowed URL or into an exclusion")
        with self.db:
            for url in candidates:
                self.db.execute("INSERT OR IGNORE INTO cloud_generated(spec_path,spec_sha256,"
                                "policy_hash,url,created) VALUES(?,?,?,?,?)",
                                (relative, sha(raw), _policy(self.ctx), url, now()))
        return {"executed": False, "queued": False, "probe_permitted": False,
                "spec_sha256": sha(raw), "candidate_count": len(candidates),
                "candidates": [{"url": url, "ownership": "unknown", "state": "unprobed"}
                               for url in candidates]}

    def _response(self, request_id):
        response = self.ctx.store.response(request_id)
        if not self.ctx.scope.is_in(response["url"]):
            raise ValueError("stored response URL is outside campaign scope")
        body_hash = response.get("body_sha256")
        if not body_hash:
            raise ValueError("stored response has no captured body")
        body = self.ctx.store.bodies_dir / body_hash
        if not body.is_file() or body.is_symlink() or body.stat().st_size > MAX_TEXT:
            raise ValueError("stored response body is missing, linked or oversized")
        raw = body.read_bytes()
        if sha(raw) != body_hash:
            raise ValueError("stored response body hash mismatch")
        parts = urlsplit(response["url"])
        snap = {"url": parts._replace(query="", fragment="").geturl(),
                "query_sha256": sha(parts.query.encode()) if parts.query else "",
                **{key: response[key] for key in ("method", "status", "body_sha256",
                                                   "body_complete", "basis")}}
        return raw, snap

    def _check_source(self, source):
        if source["kind"] == "file":
            raw, snapshot = _local(self.ctx.campaign.root, source["ref"]), {}
        elif source["kind"] == "response":
            raw, snapshot = self._response(int(source["ref"]))
        else:
            raise ValueError("unknown cloud source kind")
        if sha(raw) != source["sha256"] or canonical(snapshot) != source["snapshot"]:
            raise ValueError("source changed after extraction")
        parsed = cloud_references(raw.decode("utf-8"), source_ref="source:" + source["source_key"][:24],
                                  media_type=source["media_type"], historical=bool(source["historical"]))
        expected = sorted((r["provider"], r["resource_kind"], r["native_identifier"],
                           canonical(r["scope"]), r["selector"]["start"], r["selector"]["end"],
                           int(r["signed_context"]), r["probe_priority"],
                           canonical(r["triage_signals"])) for r in parsed)
        actual = sorted(tuple(row[key] for key in ("provider", "resource_kind", "native_identifier",
                                                   "scope", "start", "end", "signed", "score", "signals"))
                        for row in self.db.execute("SELECT * FROM cloud_refs WHERE source_id=?", (source["id"],)))
        if expected != actual:
            raise ValueError("extracted cloud references no longer match source selectors/values")

    def sync(self, limit=200, offset=0):
        if type(limit) is not int or not 1 <= limit <= 2000:
            raise ValueError("cloud sync limit must be 1..2000")
        if type(offset) is not int or offset < 0:
            raise ValueError("cloud sync offset must be nonnegative")
        rows = self.db.execute("SELECT id FROM requests WHERE body_sha256 IS NOT NULL "
                               "ORDER BY id DESC LIMIT ? OFFSET ?", (limit + 1, offset)).fetchall()
        truncated = len(rows) > limit
        rows = rows[:limit]
        gaps, added, references = [], 0, 0
        for row in rows:
            try:
                raw, snapshot = self._response(row[0])
                result = self._register("response", str(row[0]), raw, "text/plain",
                                        historical=snapshot["basis"] == "archive", snapshot=snapshot)
                added += int(result["new"])
                references += result["references"]
            except (ValueError, OSError, KeyError) as exc:
                gaps.append({"response": row[0], "reason": str(exc)})
        return {"executed": False, "sources_added": added, "references_seen": references,
                "scanned": len(rows), "offset": offset,
                "next_offset": offset + len(rows) if truncated else None,
                "truncated": truncated, "gaps": gaps,
                "inventory_complete": False}

    @staticmethod
    def _view(row):
        item = dict(row)
        item["scope"] = json.loads(item["scope"])
        snapshot = json.loads(item.pop("snapshot"))
        item["capture_complete"] = (bool(snapshot["body_complete"])
                                    if item["source_kind"] == "response"
                                    and snapshot.get("body_complete") is not None else
                                    True if item["source_kind"] == "file" else None)
        item["triage_signals"] = json.loads(item.pop("signals"))
        item["signed_context"] = bool(item.pop("signed"))
        item["historical"] = bool(item["historical"])
        item["selector"] = {"start": item.pop("start"), "end": item.pop("end")}
        item["ownership"] = "unknown"
        return item

    def plan(self, limit=25):
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("cloud plan limit must be 1..200")
        rows = self.db.execute(
            "SELECT r.*,s.kind AS source_kind,s.ref AS source_ref,s.sha256 AS source_sha256,"
            "s.historical,s.snapshot,s.created FROM cloud_refs r JOIN cloud_sources s ON s.id=r.source_id "
            "ORDER BY r.score DESC,r.provider,r.resource_kind,r.native_identifier,r.id LIMIT ?", (limit,))
        generated = [dict(r) for r in self.db.execute(
            "SELECT id,url,policy_hash FROM cloud_generated ORDER BY id LIMIT ?", (limit,))]
        for candidate in generated:
            candidate["stale"] = candidate.pop("policy_hash") != _policy(self.ctx)
            candidate.update({"ownership": "unknown", "state": "unprobed", "queued": False})
        return {"executed": False, "candidates": [self._view(r) for r in rows],
                "generated_candidates": generated,
                "total": self.db.execute("SELECT count(*) FROM cloud_refs").fetchone()[0],
                "inventory_complete": False, "coverage_complete": False,
                "priority_is_severity": False}

    def show(self, reference_id):
        row = self.db.execute("SELECT r.*,s.kind AS source_kind,s.ref AS source_ref,"
                              "s.sha256 AS source_sha256,s.historical,s.snapshot,s.created "
                              "FROM cloud_refs r JOIN cloud_sources s ON s.id=r.source_id "
                              "WHERE r.id=?", (reference_id,)).fetchone()
        if not row:
            raise ValueError("unknown cloud reference ID")
        events = []
        for event in self.db.execute("SELECT * FROM cloud_events WHERE ref_id=? ORDER BY id", (reference_id,)):
            data = json.loads(event["data"])
            events.append({"id": event["id"], "state": event["state"], "family": event["family"],
                           "channel": event["channel"], "data": data,
                           "stale": event["policy_hash"] != _policy(self.ctx)})
        return {"reference": self._view(row), "events": events, "finding_promoted": False}

    def _artifact(self, path):
        raw = _local(self.ctx.campaign.root, path)
        return {"path": path, "sha256": sha(raw), "bytes": len(raw)}, raw

    def record_file(self, relative):
        raw = _local(self.ctx.campaign.root, relative)
        if len(raw) > MAX_TEXT:
            raise ValueError("cloud event exceeds two megabytes")
        return self.record(json.loads(raw))

    def record(self, data):
        _only(data, {"schema", "reference", "case", "state", "channel", "operation",
                     "objective_tier", "grant", "requests", "artifacts", "marker",
                     "control_marker", "content_assessment", "reason", "request_ids",
                     "external_refs"}, "cloud event")
        if data.get("schema") != 1 or type(data.get("reference")) is not int:
            raise ValueError("cloud event needs schema=1 and reference ID")
        item = self.show(data["reference"])["reference"]
        source = self.db.execute("SELECT * FROM cloud_sources WHERE id=?", (item["source_id"],)).fetchone()
        try:
            self._check_source(source)
        except (OSError, KeyError) as exc:
            raise ValueError("cloud source integrity is missing") from exc
        family, state, channel = data.get("case"), data.get("state"), data.get("channel")
        if family not in FAMILIES or state not in STATES or channel not in CHANNELS:
            raise ValueError("cloud event needs known case/state/channel")
        tier = data.get("objective_tier", "read")
        if tier not in OBJECTIVES:
            raise ValueError("cloud event needs a known objective tier")
        op = data.get("operation")
        _only(op, {"principal", "action", "resource_id", "method", "request_url",
                   "version"}, "cloud operation")
        for field in ("principal", "action", "resource_id", "method"):
            _label(op.get(field), field)
        if op["resource_id"] != item["native_identifier"]:
            raise ValueError("event resource must bind the exact reference identifier")
        if op["method"] not in HTTP_METHODS:
            raise ValueError("event HTTP method is not supported")
        if "version" in op:
            _label(op["version"], "version")
        reason = data.get("reason", "")
        if (not isinstance(reason, str) or len(reason) > 200 or
                any(c in reason for c in "\r\n") or
                any(regex.search(reason) for regex in SECRET_PATTERNS.values())):
            raise ValueError("event reason must be one short value-free line")
        request_url = op.get("request_url", "")
        if request_url and (not isinstance(request_url, str) or len(request_url) > 500 or
                            urlsplit(request_url).query or urlsplit(request_url).fragment or
                            not self.ctx.scope.is_in(request_url)):
            raise ValueError("event request URL must be a scoped URL without bearer/query")
        requests = data.get("requests", 0)
        if type(requests) is not int or not 0 <= requests <= 10000:
            raise ValueError("event request declaration must be 0..10000")
        if state == "blocked" and requests:
            raise ValueError("blocked event cannot declare an unreferenced live attempt")
        grant = data.get("grant", "")
        ids, external = data.get("request_ids", []), data.get("external_refs", [])
        if not isinstance(ids, list) or not isinstance(external, list):
            raise ValueError("request references must be lists")
        if channel == "native" and state != "blocked":
            if (len(ids) != requests or len(ids) != len(set(map(str, ids))) or external or
                    any(type(rid) is not int or rid < 1 for rid in ids)):
                raise ValueError("native events need one distinct stored request ID per declared send")
            for rid in ids:
                receipt = self.ctx.store.response(rid)
                if (receipt["url"] != request_url or receipt["method"] != op["method"] or
                        receipt["basis"] != "target-http" or receipt["status"] is None or
                        receipt["error"] is not None):
                    raise ValueError("native request ID must match a completed scoped target-http exchange")
        elif channel == "burp" and state != "blocked":
            if (ids or not external or len(external) != requests or
                    len(external) != len(set(map(str, external))) or any(
                        not isinstance(ref, str) or not ref.startswith("burp:") or
                        not _LABEL.fullmatch(ref) for ref in external)):
                raise ValueError("Burp events need distinct source-labelled external refs")
        elif ids or external:
            raise ValueError("offline/blocked events cannot borrow live request references")
        if channel in ("native", "burp") and (state != "blocked" or requests):
            cfg = self.ctx.campaign.raw.get("cloud", {})
            if (not self.ctx.campaign.raw.get("program_url") or not self.ctx.campaign.raw.get("rules")
                    or not cfg.get("rules_reviewed") or grant not in cfg.get("grants", [])
                    or grant not in GRANTS or self.ctx.policy.mode == "passive"
                    or not request_url or op["method"] not in self.ctx.policy.allowed_methods
                    or requests < 1):
                raise ValueError("live cloud evidence requires reviewed rules, grant, exact scope, "
                                 "active mode, allowed method and declared requests")
        elif channel in ("offline", "owned-lab") and requests:
            raise ValueError("offline/owned-lab evidence cannot declare target requests")
        content = data.get("content_assessment", {})
        _only(content, {"content_class", "intended_publicness", "confidence"}, "content assessment")
        if (content.get("content_class", "unknown") not in CONTENT or
                content.get("intended_publicness", "unknown") not in PUBLICNESS or
                content.get("confidence", "hint") not in
                ("hint", "source-supported", "owner-bound", "controlled")):
            raise ValueError("invalid content assessment")
        artifacts = data.get("artifacts", {})
        if not isinstance(artifacts, dict) or set(artifacts) - ROLES:
            raise ValueError("cloud artifact roles are invalid")
        receipts, raw = {}, {}
        for role, path in artifacts.items():
            receipts[role], raw[role] = self._artifact(path)
        if sum(receipt["bytes"] for receipt in receipts.values()) > 25_000_000:
            raise ValueError("cloud event exceeds 25MB declared evidence")
        if state == "canary-proved":
            required = {"owner-baseline", "test", "replay", "negative-control"}
            if not required <= receipts.keys() or len({v["sha256"] for v in receipts.values()}) != len(receipts):
                raise ValueError("canary proof needs distinct baseline/test/replay/negative control")
            marker, control = data.get("marker"), data.get("control_marker")
            if not valid_marker(marker) or not valid_marker(control) or marker == control:
                raise ValueError("canary proof needs two distinct owned markers")
            if (marker.encode() not in raw["test"] or marker.encode() not in raw["replay"]
                    or marker.encode() in raw["owner-baseline"]
                    or marker.encode() in raw["negative-control"]
                    or control.encode() not in raw["negative-control"]):
                raise ValueError("canary markers are not independently present in proof/control")
            if op["method"] in ("POST", "PUT", "PATCH", "DELETE") and not {
                    "before", "after", "cleanup"} <= receipts.keys():
                raise ValueError("canary write needs independent before/after/cleanup receipts")
            if op["method"] in ("POST", "PUT", "PATCH", "DELETE") and (
                    marker.encode() in raw["before"] or marker.encode() not in raw["after"] or
                    marker.encode() in raw["cleanup"]):
                raise ValueError("canary write needs marker absent before, present after, absent after cleanup")
        elif data.get("marker") or data.get("control_marker"):
            raise ValueError("markers are reserved for canary-proved evidence")
        event = {"reference": data["reference"], "case": family, "state": state,
                 "channel": channel, "objective_tier": tier, "operation": op,
                 "grant": grant, "requests": requests, "artifacts": receipts,
                 "request_ids": ids, "external_refs": external,
                 "content_assessment": {"content_class": content.get("content_class", "unknown"),
                                        "intended_publicness": content.get("intended_publicness", "unknown"),
                                        "confidence": content.get("confidence", "hint")},
                 "marker": data.get("marker", ""), "control_marker": data.get("control_marker", ""),
                 "reason": reason, "source_sha256": item["source_sha256"],
                 "policy_hash": _policy(self.ctx)}
        h = sha(canonical(event).encode())
        prior = self.db.execute("SELECT id FROM cloud_events WHERE event_hash=?", (h,)).fetchone()
        if prior:
            return {"event": prior[0], "executed": False, "finding_promoted": False,
                    "semantic_review_required": True, "deduplicated": True}
        if channel in ("native", "burp"):
            spent = sum(json.loads(e[0])["requests"] for e in self.db.execute(
                "SELECT data FROM cloud_events WHERE channel IN ('native','burp')"))
            if spent + requests > self.ctx.campaign.raw.get("cloud", {}).get("budget", 0):
                raise ValueError("cloud shared declared budget exhausted")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO cloud_events(ref_id,family,state,channel,event_hash,"
                            "policy_hash,data,created) VALUES(?,?,?,?,?,?,?,?)",
                            (data["reference"], family, state, channel, h, _policy(self.ctx),
                             canonical(event), now()))
        row = self.db.execute("SELECT id FROM cloud_events WHERE event_hash=?", (h,)).fetchone()
        return {"event": row[0], "executed": False, "finding_promoted": False,
                "semantic_review_required": True}

    def verify(self):
        issues = []
        for generated in self.db.execute("SELECT * FROM cloud_generated"):
            try:
                if sha(_local(self.ctx.campaign.root, generated["spec_path"])) != generated["spec_sha256"]:
                    raise ValueError("generation spec changed")
            except (ValueError, OSError) as exc:
                issues.append({"generated": generated["id"], "reason": str(exc)})
            if generated["policy_hash"] != _policy(self.ctx):
                issues.append({"generated": generated["id"], "reason": "policy/scope changed; stale"})
        for source in self.db.execute("SELECT * FROM cloud_sources"):
            try:
                self._check_source(source)
            except (ValueError, OSError, KeyError, UnicodeError) as exc:
                issues.append({"source": source["id"], "reason": str(exc)})
        for event in self.db.execute("SELECT * FROM cloud_events"):
            try:
                data = json.loads(event["data"])
                if not isinstance(data, dict) or not isinstance(data.get("artifacts"), dict):
                    raise ValueError("cloud event snapshot is not an object with artifacts")
            except (TypeError, ValueError) as exc:
                issues.append({"event": event["id"], "reason": f"invalid event snapshot: {exc}"})
                continue
            if sha(canonical(data).encode()) != event["event_hash"]:
                issues.append({"event": event["id"], "reason": "event snapshot changed"})
            if (data.get("reference") != event["ref_id"] or data.get("case") != event["family"] or
                    data.get("state") != event["state"] or data.get("channel") != event["channel"] or
                    data.get("policy_hash") != event["policy_hash"]):
                issues.append({"event": event["id"], "reason": "event columns diverge from snapshot"})
            for role, receipt in data["artifacts"].items():
                try:
                    if sha(_local(self.ctx.campaign.root, receipt["path"])) != receipt["sha256"]:
                        raise ValueError("evidence artifact changed")
                except (ValueError, OSError) as exc:
                    issues.append({"event": event["id"], "role": role, "reason": str(exc)})
            if event["policy_hash"] != _policy(self.ctx):
                issues.append({"event": event["id"], "reason": "policy/scope changed; stale"})
        return {"ok": not issues, "issues": issues, "executed": False,
                "finding_promoted": False, "provider_semantics_verified": False}

    def status(self, limit=25):
        plan = self.plan(limit)
        return {"executed": False, "candidates": plan["total"],
                "generated_candidates": self.db.execute("SELECT count(*) FROM cloud_generated").fetchone()[0],
                "sources": self.db.execute("SELECT count(*) FROM cloud_sources").fetchone()[0],
                "events": self.db.execute("SELECT count(*) FROM cloud_events").fetchone()[0],
                "top": plan["candidates"], "inventory_complete": False,
                "coverage_complete": False, "finding_promoted": False}
