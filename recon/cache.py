"""Offline cache-deception/poisoning evidence ledger (owned-lab first slice).

Does not contact a target, prime or purge a shared cache, dispatch requests or
promote findings. Every referenced response and artifact is a campaign-local,
hash-bound snapshot; every URL is checked against the campaign scope. Live-
labelled receipts are operator-supplied assertions and their declared budget is
NOT an executor. Cache layer/key/semantics remain unverified until an independent
owned edge/origin observation and the negative/positive controls agree.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from .callbacks import local_bytes, valid_marker
from .campaign import HTTP_METHODS, norm_path
from .extract import SECRET_PATTERNS
from .store import now

# CP: poisoning hypotheses (unkeyed query/header/method/representation/layer).
# CD: deception hypotheses (static suffix, path normalization, auth/Vary, layers).
FAMILIES = tuple("CP-%02d" % i for i in range(1, 7)) + tuple("CD-%02d" % i for i in range(1, 7))
STATES = ("blocked", "inconclusive", "negative", "observed", "canary-proved")
CHANNELS = ("offline", "owned-lab", "native", "burp")
GRANTS = frozenset({"read", "write", "discovery", "chain", "impact", "burst"})
ROLES = frozenset({"owner-baseline", "low-baseline", "baseline", "test", "replay",
                   "cross-viewer", "negative-control", "legitimate-control",
                   "positive-control", "before", "after", "cleanup", "identity", "audit"})
CONTENT = frozenset({"public-asset", "private-content", "authenticated-content",
                     "synthetic", "error-page", "unknown"})
PUBLICNESS = frozenset({"public-intended", "private", "unknown"})
OBJECTIVES = frozenset({"disclose", "poison", "persist", "deceive", "impact-assess"})
CACHE_HEADERS = frozenset({
    "age", "cache-control", "cdn-cache-control", "cf-cache-status", "date", "etag",
    "expires", "pragma", "surrogate-control", "vary", "via", "warning", "x-cache",
    "x-cache-status", "cache-status", "x-served-by", "x-proxy-cache",
    "x-fastly-request-id", "akamai-cache-status", "server-timing"})
_LABEL = re.compile(r"^[A-Za-z0-9_.:/@+-]{1,200}$")
MAX_TEXT = 2_000_000
SCHEMA = """
CREATE TABLE IF NOT EXISTS cache_events(
  id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES requests(id),
  family TEXT NOT NULL, state TEXT NOT NULL, channel TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE, policy_hash TEXT NOT NULL,
  data TEXT NOT NULL, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS cache_events_request ON cache_events(request_id);
"""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _local(root, relative):
    """Read within campaign, refusing symlinks even when they resolve inside it."""
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("cache evidence needs a campaign-relative file")
    base = Path(root).resolve()
    path = base / relative
    if any(part in ("..", "") for part in Path(relative).parts):
        raise ValueError("cache evidence path escapes campaign")
    for component in (path, *path.parents):
        if component == base:
            break
        if component.is_symlink():
            raise ValueError("cache evidence symlinks are not accepted")
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
                          "cache": ctx.campaign.raw.get("cache", {})}).encode())


class CacheLedger:
    def __init__(self, ctx):
        self.ctx, self.db = ctx, ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()

    def _response(self, request_id):
        """Return (raw body, redacted snapshot) for a stored, scoped response.

        The snapshot binds the exact origin/path/query hash, method, status and
        body hash plus a *value-free* fingerprint of cache-relevant headers.
        Raw header values are intentionally not copied into event data.
        """
        if type(request_id) is not int or request_id < 1:
            raise ValueError("cache evidence needs a stored request ID")
        try:
            response = self.ctx.store.response(request_id)
        except KeyError:
            raise ValueError(f"no stored scoped response {request_id}") from None
        if response.get("error"):
            raise ValueError("stored response records a failed exchange")
        if not self.ctx.scope.is_in(response["url"]):
            raise ValueError("stored response URL is outside campaign scope")
        if any(regex.search(response["url"]) for regex in SECRET_PATTERNS.values()):
            raise ValueError("stored response URL contains a secret-like value; redact it first")
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
        headers = response.get("resp_headers") or {}
        if not isinstance(headers, dict):
            raise ValueError("stored response has no header map")
        cache_headers = {key: headers[key] for key in sorted(headers)
                         if key.lower() in CACHE_HEADERS}
        snapshot = {
            "url": parts._replace(query="", fragment="").geturl(),
            "path": norm_path(parts.path, casefold=False),
            "query_sha256": sha(parts.query.encode()) if parts.query else "",
            "query_names": sorted({name for name, _ in
                                   parse_qsl(parts.query, keep_blank_values=True)}),
            "method": response["method"],
            "status": response["status"],
            "body_sha256": body_hash,
            "body_complete": response["body_complete"],
            "basis": response["basis"],
            "header_names": sorted(headers),
            "cache_header_sha256": sha(canonical(cache_headers).encode()),
        }
        return raw, snapshot

    def _artifact(self, path):
        raw = _local(self.ctx.campaign.root, path)
        from .offline_review import ReviewJournal
        return ReviewJournal(self.ctx, "cache").retain(raw, source=path), raw

    def record_file(self, relative):
        raw = _local(self.ctx.campaign.root, relative)
        if len(raw) > MAX_TEXT:
            raise ValueError("cache event exceeds two megabytes")
        return self.record(json.loads(raw))

    def record(self, data):
        _only(data, {"schema", "reference", "case", "state", "channel", "operation",
                     "objective_tier", "grant", "requests", "artifacts", "marker",
                     "control_marker", "content_assessment", "reason", "request_ids",
                     "external_refs"}, "cache event")
        if data.get("schema") != 1 or type(data.get("reference")) is not int:
            raise ValueError("cache event needs schema=1 and a stored request ID")
        response_raw, snapshot = self._response(data["reference"])
        family, state, channel = data.get("case"), data.get("state"), data.get("channel")
        if family not in FAMILIES or state not in STATES or channel not in CHANNELS:
            raise ValueError("cache event needs known case/state/channel")
        tier = data.get("objective_tier", "disclose")
        if tier not in OBJECTIVES:
            raise ValueError("cache event needs a known objective tier")
        op = data.get("operation")
        _only(op, {"principal", "action", "resource_id", "method", "request_url",
                   "variant"}, "cache operation")
        for field in ("principal", "action", "method"):
            _label(op.get(field), field)
        if op["resource_id"] != snapshot["path"]:
            raise ValueError("event resource must bind the exact referenced path")
        if op["method"] not in HTTP_METHODS or op["method"] != snapshot["method"]:
            raise ValueError("event method must match the stored response")
        if "variant" in op:
            _label(op["variant"], "variant")
        reason = data.get("reason", "")
        if (not isinstance(reason, str) or len(reason) > 200 or
                any(c in reason for c in "\r\n") or
                any(regex.search(reason) for regex in SECRET_PATTERNS.values())):
            raise ValueError("event reason must be one short value-free line")
        request_url = op.get("request_url", "") or snapshot["url"]
        if (not isinstance(request_url, str) or len(request_url) > 500 or
                urlsplit(request_url).query or urlsplit(request_url).fragment or
                request_url != snapshot["url"] or not self.ctx.scope.is_in(request_url)):
            raise ValueError("event request URL must bind the scoped stored resource")
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
            if data["reference"] not in ids:
                raise ValueError("cache reference must be one of the declared native requests")
            for rid in ids:
                receipt = self.ctx.store.response(rid)
                if (receipt["basis"] != "target-http" or receipt["status"] is None or
                        receipt["error"] is not None or
                        not self.ctx.scope.is_in(receipt["url"])):
                    raise ValueError("native request ID must match a completed scoped "
                                     "target-http exchange")
            if state == "canary-proved" and requests < 2:
                raise ValueError("cache proof needs independent marker and viewer exchanges")
        elif channel == "burp" and state != "blocked":
            if (ids or not external or len(external) != requests or
                    len(external) != len(set(map(str, external))) or any(
                        not isinstance(ref, str) or not ref.startswith("burp:") or
                        not _LABEL.fullmatch(ref) for ref in external)):
                raise ValueError("Burp events need distinct source-labelled external refs")
        elif ids or external:
            raise ValueError("offline/blocked events cannot borrow live request references")
        if channel in ("native", "burp") and (state != "blocked" or requests):
            cfg = self.ctx.campaign.raw.get("cache", {})
            if (not self.ctx.campaign.raw.get("program_url") or not self.ctx.campaign.raw.get("rules")
                    or not cfg.get("rules_reviewed") or grant not in cfg.get("grants", [])
                    or grant not in GRANTS or self.ctx.policy.mode == "passive"
                    or not request_url or op["method"] not in self.ctx.policy.allowed_methods
                    or requests < 1):
                raise ValueError("live cache evidence requires reviewed rules, grant, exact scope, "
                                 "active mode, allowed method and declared requests")
        elif channel in ("offline", "owned-lab") and requests:
            raise ValueError("offline/owned-lab evidence cannot declare target requests")
        content = data.get("content_assessment", {})
        _only(content, {"content_class", "intended_publicness", "confidence"},
              "content assessment")
        if (content.get("content_class", "unknown") not in CONTENT or
                content.get("intended_publicness", "unknown") not in PUBLICNESS or
                content.get("confidence", "hint") not in
                ("hint", "source-supported", "owner-bound", "controlled")):
            raise ValueError("invalid content assessment")
        artifacts = data.get("artifacts", {})
        if not isinstance(artifacts, dict) or set(artifacts) - ROLES:
            raise ValueError("cache artifact roles are invalid")
        receipts, raw = {}, {}
        for role, path in artifacts.items():
            receipts[role], raw[role] = self._artifact(path)
        if sum(receipt["bytes"] for receipt in receipts.values()) > 25_000_000:
            raise ValueError("cache event exceeds 25MB declared evidence")
        if state == "canary-proved":
            if snapshot["body_complete"] not in (True,):
                raise ValueError("cache proof needs a complete captured viewer body")
            required = {"baseline", "test", "replay", "cross-viewer",
                        "negative-control", "positive-control"}
            if (not required <= receipts.keys() or
                    len({v["sha256"] for v in receipts.values()}) != len(receipts)):
                raise ValueError("cache proof needs distinct baseline/test/replay/cross-viewer/"
                                 "negative/positive controls")
            marker, control = data.get("marker"), data.get("control_marker")
            if not valid_marker(marker) or not valid_marker(control) or marker == control:
                raise ValueError("cache proof needs two distinct owned markers")
            if (marker.encode() not in raw["test"] or marker.encode() not in raw["replay"]
                    or marker.encode() not in raw["cross-viewer"]
                    or marker.encode() in raw["baseline"]
                    or marker.encode() in raw["negative-control"]
                    or marker.encode() in raw["positive-control"]
                    or control.encode() not in raw["negative-control"]
                    or control.encode() not in raw["positive-control"]):
                raise ValueError("cache markers are not independently present in proof/controls")
            if receipts["cross-viewer"]["sha256"] != snapshot["body_sha256"]:
                raise ValueError("cross-viewer evidence must be the referenced stored response body")
            if family.startswith("CD-") and content.get("intended_publicness") != "private":
                raise ValueError("cache deception proof requires intended-private content")
            if op["method"] in ("POST", "PUT", "PATCH", "DELETE") and not {
                    "before", "after", "cleanup"} <= receipts.keys():
                raise ValueError("cache write needs independent before/after/cleanup receipts")
            if op["method"] in ("POST", "PUT", "PATCH", "DELETE") and (
                    marker.encode() in raw["before"] or marker.encode() not in raw["after"] or
                    marker.encode() in raw["cleanup"]):
                raise ValueError("cache write needs marker absent before, present after, "
                                 "absent after cleanup")
        elif data.get("marker") or data.get("control_marker"):
            raise ValueError("markers are reserved for canary-proved evidence")
        event = {"reference": data["reference"], "case": family, "state": state,
                 "channel": channel, "objective_tier": tier, "operation": op,
                 "grant": grant, "requests": requests, "artifacts": receipts,
                 "request_ids": ids, "external_refs": external,
                 "content_assessment": {"content_class": content.get("content_class", "unknown"),
                                        "intended_publicness": content.get("intended_publicness",
                                                                           "unknown"),
                                        "confidence": content.get("confidence", "hint")},
                 "marker": data.get("marker", ""), "control_marker": data.get("control_marker", ""),
                 "reason": reason, "response": snapshot,
                 "policy_hash": _policy(self.ctx)}
        h = sha(canonical(event).encode())
        prior = self.db.execute("SELECT id FROM cache_events WHERE event_hash=?", (h,)).fetchone()
        if prior:
            return {"event": prior[0], "executed": False, "finding_promoted": False,
                    "semantic_review_required": True, "deduplicated": True}
        if channel in ("native", "burp"):
            spent = sum(json.loads(row[0])["requests"] for row in self.db.execute(
                "SELECT data FROM cache_events WHERE channel IN ('native','burp')"))
            if spent + requests > self.ctx.campaign.raw.get("cache", {}).get("budget", 0):
                raise ValueError("cache shared declared budget exhausted")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO cache_events(request_id,family,state,channel,"
                            "event_hash,policy_hash,data,created) VALUES(?,?,?,?,?,?,?,?)",
                            (data["reference"], family, state, channel, h, _policy(self.ctx),
                             canonical(event), now()))
        row = self.db.execute("SELECT id FROM cache_events WHERE event_hash=?", (h,)).fetchone()
        return {"event": row[0], "executed": False, "finding_promoted": False,
                "semantic_review_required": True}

    def show(self, reference):
        _, snapshot = self._response(reference)
        events = []
        for event in self.db.execute("SELECT * FROM cache_events WHERE request_id=? ORDER BY id",
                                     (reference,)):
            events.append({"id": event["id"], "state": event["state"], "family": event["family"],
                           "channel": event["channel"], "data": json.loads(event["data"]),
                           "stale": event["policy_hash"] != _policy(self.ctx)})
        return {"reference": {"id": reference, **snapshot}, "events": events,
                "finding_promoted": False}

    def verify(self):
        issues = []
        for event in self.db.execute("SELECT * FROM cache_events"):
            try:
                data = json.loads(event["data"])
                if not isinstance(data, dict) or not isinstance(data.get("artifacts"), dict):
                    raise ValueError("cache event snapshot is not an object with artifacts")
            except (TypeError, ValueError) as exc:
                issues.append({"event": event["id"], "reason": f"invalid event snapshot: {exc}"})
                continue
            if sha(canonical(data).encode()) != event["event_hash"]:
                issues.append({"event": event["id"], "reason": "event snapshot changed"})
            if (data.get("reference") != event["request_id"] or
                    data.get("case") != event["family"] or
                    data.get("state") != event["state"] or
                    data.get("channel") != event["channel"] or
                    data.get("policy_hash") != event["policy_hash"]):
                issues.append({"event": event["id"], "reason": "event columns diverge from snapshot"})
            try:
                _, snapshot = self._response(int(event["request_id"]))
                if canonical(snapshot) != canonical(data.get("response", {})):
                    raise ValueError("stored response changed after recording")
            except (ValueError, OSError, KeyError, TypeError) as exc:
                issues.append({"event": event["id"], "reason": str(exc)})
            for role, receipt in data["artifacts"].items():
                try:
                    if sha(_local(self.ctx.campaign.root, receipt["path"])) != receipt["sha256"]:
                        raise ValueError("evidence artifact changed")
                    if "source" in receipt and sha(_local(
                            self.ctx.campaign.root, receipt["source"])) != receipt["sha256"]:
                        raise ValueError("original evidence source changed")
                except (ValueError, OSError) as exc:
                    issues.append({"event": event["id"], "role": role, "reason": str(exc)})
            if event["policy_hash"] != _policy(self.ctx):
                issues.append({"event": event["id"], "reason": "policy/scope changed; stale"})
        return {"ok": not issues, "issues": issues, "executed": False,
                "finding_promoted": False, "cache_semantics_verified": False}

    def status(self, limit=25):
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("cache status limit must be 1..200")
        states = {state: 0 for state in STATES}
        for row in self.db.execute("SELECT state,count(*) FROM cache_events GROUP BY state"):
            states[row[0]] = row[1]
        top = [{"id": row[0], "reference": row[1], "state": row[2], "family": row[3],
                "channel": row[4]} for row in self.db.execute(
                    "SELECT id,request_id,state,family,channel FROM cache_events "
                    "ORDER BY id DESC LIMIT ?", (limit,))]
        return {"executed": False, "events": sum(states.values()), "by_state": states,
                "top": top, "finding_promoted": False, "cache_semantics_verified": False}
