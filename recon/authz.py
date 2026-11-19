"""Offline access-control/mass-assignment inventory and evidence ledger.

No HTTP client, browser, scanner, credential reader or automatic finding promotion.
Captured request *names* are inventory; observed outcomes remain operator assertions
with local proof-role and integrity checks, not certified exploit verdicts.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlencode, urlsplit

from .callbacks import local_bytes, valid_marker
from .campaign import HTTP_METHODS, validate_authz
from .score import applicable_classes, is_inferred_only
from .store import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS authz_targets(
 id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
 url TEXT NOT NULL, method TEXT NOT NULL, selector TEXT NOT NULL,
 resource TEXT NOT NULL, basis TEXT NOT NULL, classes TEXT NOT NULL,
 sources TEXT NOT NULL, created TEXT NOT NULL,
 UNIQUE(asset_id,method,url,selector));
CREATE TABLE IF NOT EXISTS authz_paths(
 id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES authz_targets(id),
 kind TEXT NOT NULL, detail TEXT NOT NULL, basis TEXT NOT NULL,
 UNIQUE(target_id,kind,detail));
CREATE TABLE IF NOT EXISTS authz_contexts(
 id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL REFERENCES authz_targets(id),
 representation TEXT NOT NULL, auth TEXT NOT NULL, account TEXT NOT NULL,
 role TEXT NOT NULL, tenant TEXT NOT NULL, workflow TEXT NOT NULL,
 capture_key TEXT NOT NULL, basis TEXT NOT NULL, observation_ids TEXT NOT NULL,
 facets TEXT NOT NULL, updated TEXT NOT NULL,
 UNIQUE(target_id,representation,auth,account,role,tenant,workflow,capture_key));
CREATE TABLE IF NOT EXISTS authz_events(
 id INTEGER PRIMARY KEY, context_id INTEGER NOT NULL REFERENCES authz_contexts(id),
 case_id TEXT NOT NULL, variant TEXT NOT NULL, state TEXT NOT NULL,
 grant TEXT NOT NULL, parent_id INTEGER REFERENCES authz_events(id),
 impact TEXT NOT NULL, marker TEXT NOT NULL, proof_basis TEXT NOT NULL,
 policy_hash TEXT NOT NULL, facet_hash TEXT NOT NULL,
 requests_declared INTEGER NOT NULL, tool_refs TEXT NOT NULL,
 owner TEXT NOT NULL, root_key TEXT NOT NULL, related_cases TEXT NOT NULL,
 note TEXT NOT NULL, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS authz_events_context ON authz_events(context_id,case_id,variant,id);
CREATE TABLE IF NOT EXISTS authz_artifacts(
 event_id INTEGER NOT NULL REFERENCES authz_events(id), role TEXT NOT NULL,
 path TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL,
 source_path TEXT NOT NULL, PRIMARY KEY(event_id,role));
"""

CASES = {
    "ac-unauth": ("access-control", "", 4),
    "ac-role": ("access-control", "", 5),
    "ac-tenant": ("access-control", "", 5),
    "ac-method": ("access-control", "", 3),
    "ac-version": ("access-control", "", 3),
    "ac-projection": ("access-control", "", 3),
    "ac-transport": ("access-control", "", 3),
    "ac-surface": ("access-control", "", 4),
    "ma-privileged-field": ("mass-assignment", "write-proof", 6),
}
CHAIN = ("token-use", "lateral", "persistence")
# Only these variant prefixes select a probe not already supported by capture.
VARIANT_GRANTS = {"matrix": "method-matrix", "expand": "sibling-expand",
                  "fuzz": "representation-fuzz", "extract": "read-extraction",
                  "mutate": "id-mutation"}
FAMILIES_FOR_CASE = {"ac-unauth": {"read-extraction"},
                     "ac-method": {"method-matrix"},
                     "ac-version": {"sibling-expand"},
                     "ac-tenant": {"id-mutation"},
                     "ac-transport": {"representation-fuzz"},
                     "ac-surface": {"read-extraction"}}
HIGH_VALUE_PATH = re.compile(r"admin|secret|api.?key|token|credential|tenant|billing|transfer|"
                             r"invite|export|report|internal|impersonat", re.I)
STATES = ("attempted", "observed", "negative", "blocked", "inconclusive", "n-a")
ROLES = ("baseline", "test", "control", "before", "after", "request", "trace")
IMPACTS = ("none", "config", "topology", "pii", "secret", "admin", "bulk")
SENSITIVE = {"pii", "secret", "admin", "bulk"}
SECRET_RE = re.compile(rb"-----BEGIN [A-Z ]+PRIVATE KEY-----|(?:Bearer|Basic)\s+[A-Za-z0-9._~+/-]{12,}|"
                       rb"\bAKIA[A-Z0-9]{16}\b|(?:password|api[_-]?key|secret)\s*[=:]\s*[^\s\[<]{8,}", re.I)
MAX_TARGETS = 2000
MAX_CONTEXTS = 50


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _version(url: str) -> str:
    return next((s for s in urlsplit(url).path.split("/") if re.fullmatch(r"v\d+", s, re.I)), "")


def _write_operation(target, case="") -> bool:
    """Conservative write gate; a named GraphQL query over POST is read-only."""
    if case == "persistence":
        return True
    if case == "ma-privileged-field":
        return True
    selector = target["selector"]
    return (target["method"] in ("POST", "PUT", "PATCH", "DELETE") and
            not (target["method"] == "POST" and re.match(r"^query(?:\s|$)", selector, re.I)))


def _labels(o: Dict[str, Any]) -> tuple:
    c = o.get("context") or {}
    meta = c.get("csrf_meta") or {}
    representation = meta.get("content_type") or (
        "none" if (o.get("method") or "").upper() in ("GET", "HEAD", "OPTIONS") else "unknown")
    return (representation, meta.get("auth") or "unknown",
            o.get("account") or "unknown", c.get("role") or "unknown",
            c.get("tenant") or "unknown", c.get("workflow_state") or "unknown")


def _safe_text(value: str, what: str, limit=2000):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"{what} must be a bounded text value")
    if SECRET_RE.search(value.encode()):
        raise ValueError(f"{what} appears to contain a raw secret; redact it")


def _proof_issue(event, target, blobs) -> str:
    """Structural integrity only; these bytes cannot establish server causality."""
    if event["state"] not in ("observed", "negative"):
        return ""
    marker = event["marker"]
    if not valid_marker(marker) or not event["proof_basis"].strip():
        return "missing marker/proof basis"
    if not {"baseline", "test", "control"} <= set(blobs):
        return "proof roles missing"
    baseline, test, control = (blobs[role] for role in ("baseline", "test", "control"))
    if (len({hashlib.sha256(blob).digest() for blob in (baseline, test, control)}) != 3 or
            marker.encode() not in baseline or marker.encode() not in test or
            marker.encode() in control):
        return "marker/control mismatch"
    if _write_operation(target, event["case_id"]):
        if not {"before", "after"} <= set(blobs):
            return "write readback missing"
        if event["state"] == "observed" and blobs["before"] == blobs["after"]:
            return "unchanged write readback"
        if marker.encode() not in blobs["before"] + blobs["after"]:
            return "write marker missing from readback"
    if event["impact"] in SENSITIVE and event["state"] == "observed" and not any(
            b"[redacted]" in blob.lower() for blob in blobs.values()):
        return "redaction marker missing"
    return ""


class AuthzLedger:
    def __init__(self, ctx):
        self.ctx = ctx
        self.db = ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.grants = validate_authz(ctx.campaign.raw.get("authz", {}))

    def _policy_hash(self):
        raw = self.ctx.campaign.raw
        return digest({k: raw.get(k) for k in ("in_scope", "out_of_scope", "excluded_bug_classes",
                                                   "rules", "authz", "policy")})

    def _target(self, target_id):
        row = self.db.execute("SELECT * FROM authz_targets WHERE id=?", (target_id,)).fetchone()
        if not row:
            raise ValueError("unknown authorization target")
        target = dict(row)
        self.ctx.scope.check(target["url"])
        return target

    def _context(self, context_id):
        if type(context_id) is not int or context_id < 1:
            raise ValueError("context ID must be positive")
        row = self.db.execute("SELECT * FROM authz_contexts WHERE id=?", (context_id,)).fetchone()
        if not row:
            raise ValueError("unknown authorization context; run authz sync")
        context = dict(row)
        return context, self._target(context["target_id"])

    def _upsert_context(self, target_id, key, observations, basis, declared):
        representation, auth, account, role, tenant, workflow, capture_key = key
        ids = sorted(o["id"] for o in observations)
        # Hash only the facets this skill depends on; a new capture or declared
        # request-shape change reopens the affected context, not unrelated ones.
        facets = digest({"observations": [(o["id"], o.get("params"), o.get("context"))
                                          for o in observations], "declared": declared})
        row = self.db.execute(
            "SELECT id,observation_ids,facets,basis FROM authz_contexts WHERE target_id=? AND "
            "representation=? AND auth=? AND account=? AND role=? AND tenant=? AND workflow=? "
            "AND capture_key=?", (target_id, *key)).fetchone()
        if row:
            if (row["observation_ids"], row["facets"], row["basis"]) != (
                    json.dumps(ids), facets, basis):
                self.db.execute("UPDATE authz_contexts SET observation_ids=?, facets=?, basis=?, "
                                "updated=? WHERE id=?", (json.dumps(ids), facets, basis, now(), row["id"]))
            return row["id"], False
        cur = self.db.execute(
            "INSERT INTO authz_contexts(target_id,representation,auth,account,role,tenant,workflow,"
            "capture_key,basis,observation_ids,facets,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (target_id, representation, auth, account, role, tenant, workflow, capture_key,
             basis, json.dumps(ids), facets, now()))
        return cur.lastrowid, True

    def sync(self):
        """Idempotent observed/declared operation inventory; no guessed siblings."""
        store = self.ctx.store
        ops = defaultdict(list)
        for op in store.operations():
            ops[op["endpoint_id"]].append(op)
        variants = defaultdict(list)
        for v in store.variants():
            variants[(v["endpoint_id"], v["method"])].append(
                (v["path"], tuple(v["query_names"])))
        stats = Counter()
        assets = [a for a in store.assets("endpoint", in_scope=True) if
                  self.ctx.scope.is_in(a["value"]) and not is_inferred_only(a) and
                  set(applicable_classes(a)) & {"access-control", "mass-assignment"}]
        assets.sort(key=lambda a: (-bool(HIGH_VALUE_PATH.search(a["value"])),
                                   -int("mass-assignment" in applicable_classes(a)), a["id"]))
        for asset in assets[:MAX_TARGETS]:
            url = asset["value"]
            classes = sorted(set(applicable_classes(asset)) & {"access-control", "mass-assignment"})
            all_observations = store.observations(asset["id"])
            observations = all_observations[-500:]
            stats["observations_capped"] += max(0, len(all_observations) - 500)
            candidates = ops[asset["id"]] or [
                {"method": m, "attrs": {}} for m in (asset["attrs"].get("methods") or ["UNKNOWN"])]
            if len(candidates) > 1:
                candidates = [c for c in candidates if c["method"] != "UNKNOWN"]
            stats["operations_capped"] += max(0, len(candidates) - 20)
            for op in candidates[:20]:
                method = op["method"].upper()
                if method not in HTTP_METHODS and method != "UNKNOWN":
                    continue
                matched = [o for o in observations if (o.get("method") or "UNKNOWN").upper() == method]
                path = urlsplit(url).path or "/"
                all_routes = sorted(set(variants.get((asset["id"], method)) or [(path, ())]))
                stats["variants_capped"] += max(0, len(all_routes) - 30)
                routes = all_routes[:30]
                # A family may contain multiple concrete paths and query shapes.
                # Only a captured path+query shape can establish that variant.
                for route, query_names in routes:
                    rows = [o for o in matched if
                            (o.get("context", {}).get("path") == route or
                             not o.get("context", {}).get("path") and len(routes) == 1) and
                            tuple(sorted(set((o.get("params") or {}).get("query") or []))) ==
                            query_names]
                    base = urlsplit(url)
                    exact_url = f"{base.scheme}://{base.netloc}{route}"
                    if query_names:
                        exact_url += "?" + urlencode([(name, "") for name in query_names])
                    if not self.ctx.scope.is_in(exact_url):
                        stats["out_of_scope_variants"] += 1
                        continue
                    selectors = {"": rows}
                    if "graphql" in path.lower() or "gql" in path.lower():
                        unnamed = []
                        for o in rows:
                            names = [name for name in
                                     (((o.get("context") or {}).get("csrf_meta") or {}).get(
                                         "graphql_operations") or [])
                                     if isinstance(name, str) and 0 < len(name) <= 120]
                            # One HTTP capture with several operations (or a batch)
                            # cannot prove the authority of any one inner selector.
                            for name in names:
                                selectors.setdefault(name, [])
                            if len(names) == 1:
                                selectors[names[0]].append(o)
                            else:
                                unnamed.append(o)
                        selectors[""] = unnamed
                    stats["selectors_capped"] += max(0, len(selectors) - 20)
                    for selector, selected_rows in list(sorted(selectors.items()))[:20]:
                        self._sync_target(asset, op, classes, exact_url, route, method, selector,
                                          selected_rows, sources=asset["attrs"].get("sources") or [],
                                          stats=stats)
        self.db.commit()
        return {"targets_added": stats["targets_added"], "contexts_added": stats["contexts_added"],
                "truncated": {"assets": max(0, len(assets) - MAX_TARGETS),
                              "observations": stats["observations_capped"],
                              "operations": stats["operations_capped"],
                              "variants": stats["variants_capped"],
                              "selectors": stats["selectors_capped"],
                              "contexts": stats["contexts_capped"],
                              "out_of_scope_variants": stats["out_of_scope_variants"]},
                "basis": "captured versus declared operations; unknowns and inferred siblings do "
                         "not prove a policy decision; no target requests", "executed": False}

    def _sync_target(self, asset, op, classes, exact_url, route, method, selector,
                     rows, sources, stats):
        resource = asset["attrs"].get("authz_resource") or route
        if not isinstance(resource, str) or len(resource) > 200 or not resource:
            resource = route
        basis = "captured" if rows else "declared"
        sources = sorted(set(sources))[:20]
        declared = {"operation": op.get("attrs") or {},
                    "spec_fields": [e for e in asset["attrs"].get("spec_fields") or []
                                    if (e.get("method") or "").upper() == method],
                    "selector": selector, "resource": resource}
        cur = self.db.execute(
            "INSERT OR IGNORE INTO authz_targets(asset_id,url,method,selector,resource,"
            "basis,classes,sources,created) VALUES(?,?,?,?,?,?,?,?,?)",
            (asset["id"], exact_url, method, selector, resource, basis,
             json.dumps(classes), json.dumps(sources), now()))
        stats["targets_added"] += cur.rowcount
        target_id = self.db.execute("SELECT id FROM authz_targets WHERE asset_id=? AND "
                                    "method=? AND url=? AND selector=?",
                                    (asset["id"], method, exact_url, selector)).fetchone()[0]
        self.db.execute("UPDATE authz_targets SET basis=?,classes=?,sources=? WHERE id=?",
                        (basis, json.dumps(classes), json.dumps(sources), target_id))
        self.db.execute("INSERT OR IGNORE INTO authz_paths(target_id,kind,detail,basis) "
                        "VALUES(?,?,?,?)", (target_id, "operation", exact_url, basis))
        groups = defaultdict(list)
        for o in rows:
            labels = _labels(o)
            capture_key = f"observation:{o['id']}" if "unknown" in labels else ""
            groups[(*labels, capture_key)].append(o)
        if not groups:
            attrs = op.get("attrs") or {}
            types = sorted(set(attrs.get("spec_content_types") or attrs.get("content_types")
                               or ["unknown"]))[:10]
            schemes = attrs.get("spec_auth") or []
            auth = schemes[0] if len(schemes) == 1 else "unknown"
            for representation in types:
                groups[(representation, auth, "unknown", "unknown", "unknown",
                        "unknown", "declared")] = []
        for key, group in list(groups.items())[:MAX_CONTEXTS]:
            _, added = self._upsert_context(target_id, key, group, basis, declared)
            stats["contexts_added"] += added
        stats["contexts_capped"] += max(0, len(groups) - MAX_CONTEXTS)

    def _readiness(self, context, target, case):
        if not self.ctx.scope.is_in(target["url"]):
            return "blocked", "target no longer in written scope"
        if case in CHAIN:
            return ("blocked" if case not in self.grants["chain_grants"] else "waiting-parent",
                    "chain grant and a proven parent are required")
        cls, family, _ = CASES[case]
        if cls not in json.loads(target["classes"]):
            return "not-applicable", "class not seeded on this operation"
        if cls in (self.ctx.campaign.raw.get("excluded_bug_classes") or []):
            return "blocked", "class excluded by program rules"
        if self.ctx.policy.mode == "passive" or target["method"] not in self.ctx.policy.allowed_methods:
            return "blocked", "campaign mode/method does not allow this operation"
        if target["method"] == "UNKNOWN" or context["basis"] != "captured":
            return "waiting-capture", "exact method/context capture required"
        if "unknown" in (context["auth"], context["account"], context["role"],
                         context["tenant"], context["workflow"], context["representation"]):
            return "waiting-prerequisite", "label account/role/tenant/workflow/authority/representation"
        if case == "ac-tenant":
            attrs = self.ctx.store.get_asset(target["asset_id"])["attrs"]
            if attrs.get("id_params") or "{id}" in urlsplit(target["url"]).path:
                return "not-applicable", "object-reference tenant tests belong to hunt-idor"
        if case in ("ac-role", "ac-tenant"):
            column = "role" if case == "ac-role" else "tenant"
            fixed = "tenant" if case == "ac-role" else "role"
            distinct = {r[column] for r in self.db.execute(
                f"SELECT DISTINCT {column} FROM authz_contexts WHERE target_id=? AND basis='captured' "
                f"AND {fixed}=? AND workflow=? AND representation=? AND auth=?",
                (target["id"], context[fixed], context["workflow"],
                 context["representation"], context["auth"])) if r[column] != "unknown"}
            if len(distinct) < 2:
                return "waiting-prerequisite", f"two labelled test-owned {column} contexts needed"
        if case == "ma-privileged-field":
            if target["method"] not in ("POST", "PUT", "PATCH", "DELETE"):
                return "not-applicable", "no write method"
            ids = json.loads(context["observation_ids"])
            obs = [o for o in self.ctx.store.observations(target["asset_id"]) if o["id"] in ids]
            if not any((o.get("params") or {}).get("body") or
                       (o.get("params") or {}).get("query") for o in obs):
                return "waiting-prerequisite", "no captured assignable field; DELETE is a candidate only"
        if _write_operation(target, case) and "write-proof" not in self.grants["probe_grants"]:
            return "blocked", "write evidence needs an explicit write-proof grant"
        if family and family not in self.grants["probe_grants"]:
            return "blocked", f"authz.probe_grants lacks {family}"
        return "ready", "operator must still check written scope, method and execution plan"

    def _event_state(self, context, case, variant):
        row = self.db.execute("SELECT * FROM authz_events WHERE context_id=? AND case_id=? "
                              "AND variant=? ORDER BY id DESC LIMIT 1",
                              (context["id"], case, variant)).fetchone()
        if not row:
            return "open", None
        if row["policy_hash"] != self._policy_hash() or row["facet_hash"] != context["facets"]:
            return "stale", row["id"]
        blobs = {}
        for a in self.db.execute("SELECT * FROM authz_artifacts WHERE event_id=?", (row["id"],)):
            try:
                data = local_bytes(self.ctx.campaign.root, a["path"])
                if len(data) != a["bytes"] or hashlib.sha256(data).hexdigest() != a["sha256"]:
                    return "stale", row["id"]
                blobs[a["role"]] = data
            except (ValueError, OSError):
                return "stale", row["id"]
        target = self._target(context["target_id"])
        if _proof_issue(row, target, blobs):
            return "stale", row["id"]
        return row["state"], row["id"]

    def plan(self, target_id=None, limit=25):
        self.sync()
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")
        targets = ([self._target(target_id)] if target_id is not None else
                   [dict(r) for r in self.db.execute("SELECT * FROM authz_targets ORDER BY id")])
        if target_id is None:
            targets.sort(key=lambda t: (-bool(HIGH_VALUE_PATH.search(t["url"])),
                                        -int("mass-assignment" in json.loads(t["classes"])), t["id"]))
            targets = targets[:limit]
        cards = []
        for target in targets:
            contexts = [dict(c) for c in self.db.execute("SELECT * FROM authz_contexts WHERE target_id=? "
                                                       "ORDER BY id LIMIT ?", (target["id"], MAX_CONTEXTS))]
            siblings = [dict(r) for r in self.db.execute(
                "SELECT id,url,method,basis FROM authz_targets WHERE resource=? AND id<>? "
                "ORDER BY id LIMIT 100",
                (target["resource"], target["id"]))
                if _origin(r["url"]) == _origin(target["url"])][:20]
            result_contexts = []
            captured_reps = {c["representation"] for c in contexts if c["basis"] == "captured"}
            for c in contexts:
                classes = json.loads(target["classes"])
                cases = []
                for case, (cls, family, priority) in CASES.items():
                    if cls not in classes:
                        continue
                    readiness, reason = self._readiness(c, target, case)
                    state, event_id = self._event_state(c, case, "default")
                    variants = []
                    seen = set()
                    for event in self.db.execute(
                            "SELECT variant FROM authz_events WHERE context_id=? AND case_id=? "
                            "ORDER BY id DESC LIMIT 30", (c["id"], case)):
                        if event["variant"] not in seen:
                            seen.add(event["variant"])
                            variant_state, variant_event = self._event_state(
                                c, case, event["variant"])
                            variants.append({"variant": event["variant"], "state": variant_state,
                                             "event_id": variant_event})
                    optional = {"ac-method": "method-matrix", "ac-version": "sibling-expand",
                                "ac-transport": "representation-fuzz", "ac-unauth": "read-extraction",
                                "ac-surface": "read-extraction"}.get(case)
                    cases.append({"case": case, "class": cls, "grant": family or None,
                                  "optional_probe": optional,
                                  "optional_probe_granted": optional in self.grants["probe_grants"]
                                  if optional else None,
                                  "readiness": readiness, "reason": reason, "state": state,
                                  "variants": variants,
                                  "event_id": event_id, "priority": priority,
                                  "next": "baseline/test/control with a test-owned marker; one dimension "
                                          "per attempt; no request is sent by this command"})
                result_contexts.append({"context_id": c["id"], "basis": c["basis"],
                                        "superseded": c["basis"] != "captured" and
                                        (c["representation"] in captured_reps or
                                         c["representation"] == "unknown" and bool(captured_reps)),
                                        "representation": c["representation"], "auth": c["auth"],
                                        "account": c["account"], "role": c["role"],
                                        "tenant": c["tenant"], "workflow": c["workflow"],
                                        "observations": json.loads(c["observation_ids"]),
                                        "cases": sorted(cases, key=lambda x: -x["priority"])})
            cards.append({"target_id": target["id"], "asset_id": target["asset_id"],
                          "url": target["url"], "method": target["method"],
                          "query_names": [k for k, _ in parse_qsl(urlsplit(target["url"]).query,
                                                                   keep_blank_values=True)],
                          "selector": target["selector"], "resource": target["resource"],
                           "version": _version(target["url"]), "basis": target["basis"],
                           "priority_basis": "path sensitivity and write candidate heuristic; not severity",
                          "classes": json.loads(target["classes"]), "sources": json.loads(target["sources"]),
                          "siblings": siblings, "contexts": result_contexts})
        total = self.db.execute("SELECT count(*) FROM authz_targets").fetchone()[0]
        return {"targets": cards, "total_targets": total, "visible_targets": len(cards),
                "truncated_targets": max(0, total - len(cards)) if target_id is None else 0,
                "grants": {k: sorted(v) if isinstance(v, frozenset) else v
                           for k, v in self.grants.items()},
                "basis": "offline impact-ranked cards; class seeding and a path sibling are leads, "
                         "not authorization or proof", "executed": False}

    def _artifacts(self, items):
        if not isinstance(items, list) or len(items) > 8:
            raise ValueError("at most eight artifacts")
        out = {}
        for item in items:
            if not isinstance(item, str):
                raise ValueError("artifacts must be ROLE=PATH strings")
            role, sep, path = item.partition("=")
            if not sep or role not in ROLES or role in out:
                raise ValueError(f"artifacts require unique ROLE=PATH with role in {ROLES}")
            if (not path or len(path) > 300 or Path(path).is_absolute() or
                    ".." in Path(path).parts or SECRET_RE.search(path.encode())):
                raise ValueError("artifact must be a short campaign-relative redacted path")
            data = local_bytes(self.ctx.campaign.root, path)
            if SECRET_RE.search(data):
                raise ValueError("artifact appears to contain an unredacted secret")
            out[role] = (path, data)
        return out

    def record(self, context_id, case, state, *, variant="default", grant="", parent_id=None,
               impact="none", marker="", proof_basis="", artifacts=None, tool_refs=None,
               requests=0, owner="", root_key="", related_cases=None, note=""):
        c, t = self._context(context_id)
        prior_attempt = self.db.execute(
            "SELECT id FROM authz_events WHERE context_id=? AND case_id=? AND variant=? AND "
            "marker=? AND state='attempted' ORDER BY id DESC LIMIT 1",
            (context_id, case, variant, marker)).fetchone()
        if case not in CASES and case not in CHAIN or state not in STATES:
            raise ValueError("unknown case or state")
        if (not isinstance(variant, str) or not 1 <= len(variant) <= 80 or
                impact not in IMPACTS or type(requests) is not int or not 0 <= requests <= 1000):
            raise ValueError("invalid variant, impact or declared request count")
        for label, text in (("note", note), ("proof basis", proof_basis),
                            ("owner", owner), ("root cause", root_key)):
            _safe_text(text, label)
        if len(root_key) > 120 or (related_cases is not None and
                                  (not isinstance(related_cases, list) or len(related_cases) > 12 or
                                   any(not isinstance(c, str) or c not in CASES and c not in CHAIN and c != "idor-bola"
                                       for c in related_cases))):
            raise ValueError("invalid root-cause key or related case IDs")
        if owner and owner not in ("hunt-access-control", "hunt-idor"):
            raise ValueError("overlap owner must be a known skill")
        if owner == "hunt-idor" and state in ("observed", "negative"):
            raise ValueError("object-reference proof belongs in hunt-idor, not this ledger")
        if state in ("blocked", "inconclusive", "n-a") and not note.strip():
            raise ValueError("blocked/inconclusive/n-a needs a reason")
        if case in CHAIN:
            if state in ("attempted", "observed", "negative"):
                if case not in self.grants["chain_grants"] or grant != case:
                    raise ValueError("chain rung needs its matching explicit authz.chain_grants grant")
                if case == "persistence" and "write-proof" not in self.grants["probe_grants"]:
                    raise ValueError("persistence evidence also needs an explicit write-proof grant")
                if case == "persistence" and t["method"] not in ("POST", "PUT", "PATCH", "DELETE"):
                    raise ValueError("persistence needs a granted write operation on disposable owned state")
                if case == "token-use" and t["method"] not in ("GET", "HEAD", "OPTIONS") and \
                        _write_operation(t, case):
                    raise ValueError("token-use exercise must be a read-only granted method")
                if parent_id is None:
                    raise ValueError("chain rung needs a parent event")
            if parent_id is not None:
                parent = self.db.execute("SELECT * FROM authz_events WHERE id=?", (parent_id,)).fetchone()
                if (not parent or parent["state"] != "observed" or
                        (case == "lateral" and parent["case_id"] != "token-use") or
                        (case == "persistence" and parent["case_id"] != "lateral") or
                        (case == "token-use" and parent["case_id"] in CHAIN)):
                    raise ValueError("chain parent must be an observed predecessor")
                if case == "token-use" and parent["impact"] != "secret":
                    raise ValueError("token-use needs a parent secret exposure, not a generic lead")
                if state in ("observed", "negative") and marker == parent["marker"]:
                    raise ValueError("chain rung needs a fresh owned marker")
                pc, pt = self._context(parent["context_id"])
                if pt["asset_id"] != t["asset_id"] or parent["policy_hash"] != self._policy_hash() or \
                        parent["facet_hash"] != pc["facets"] or \
                        self._event_state(pc, parent["case_id"], parent["variant"]) != (
                            "observed", parent_id):
                    raise ValueError("chain parent is stale or from another target")
        else:
            if parent_id is not None:
                raise ValueError("only chain rungs may name a parent")
            readiness, reason = self._readiness(c, t, case)
            family = CASES[case][1]
            variant_family = VARIANT_GRANTS.get(variant.partition(":")[0], "")
            if variant_family and variant_family not in FAMILIES_FOR_CASE.get(case, set()):
                raise ValueError("probe variant belongs to another case/skill")
            if variant_family == "method-matrix" and state in ("attempted", "observed", "negative"):
                effective = variant.split(":", 2)[1:2]
                if not effective or effective[0] not in HTTP_METHODS or \
                        effective[0] not in self.ctx.policy.allowed_methods:
                    raise ValueError("matrix variant needs a granted effective HTTP method "
                                     "(matrix:PATCH:header), not just a probe-family grant")
            required = variant_family or family
            write = _write_operation(t, case)
            if state in ("attempted", "observed", "negative") and write:
                if "write-proof" not in self.grants["probe_grants"]:
                    raise ValueError("write evidence needs an explicit write-proof grant")
                required = required or "write-proof"
            if (grant and (grant not in self.grants["probe_grants"] or grant != required)):
                raise ValueError("probe family has no matching explicit campaign grant")
            if state in ("attempted", "observed", "negative") and readiness != "ready":
                raise ValueError(f"case is {readiness}: {reason}")
            if state in ("attempted", "observed", "negative") and required and grant != required:
                raise ValueError(f"case/variant requires explicit --grant {required}")
            if state == "n-a" and readiness != "not-applicable":
                raise ValueError("n-a needs a verified missing prerequisite, not missing captures")
        if state in ("attempted", "observed", "negative") and (
                t["method"] not in self.ctx.policy.allowed_methods or self.ctx.policy.mode == "passive"):
            raise ValueError("campaign mode/method does not authorize a live attempt")
        if state == "attempted" and (requests < 1 or not valid_marker(marker)):
            raise ValueError("an attempted test needs a test-owned marker and declared request count")
        if state in ("observed", "negative") and (not valid_marker(marker) or
                                                      (requests < 1 and not prior_attempt) or
                                                      not proof_basis.strip()):
            raise ValueError("proof requires a test-owned marker, declared requests and proof basis")
        if state in ("observed", "negative") and requests == 0 and prior_attempt:
            attempt = self.db.execute("SELECT * FROM authz_events WHERE id=?",
                                      (prior_attempt["id"],)).fetchone()
            if (attempt["policy_hash"] != self._policy_hash() or attempt["facet_hash"] != c["facets"]
                    or self._event_state(c, case, variant) != ("attempted", attempt["id"])):
                raise ValueError("prior attempt is stale or superseded; cannot reuse its request receipt")
        refs = tool_refs or []
        if (not isinstance(refs, list) or len(refs) > 8 or
                any(not isinstance(ref, str) for ref in refs) or len(set(refs)) != len(refs)):
            raise ValueError("at most eight unique tool references")
        for ref in refs:
            if not isinstance(ref, str) or not re.fullmatch(r"(?:burp|native):[A-Za-z0-9._:-]{1,100}", ref):
                raise ValueError("tool refs must be labelled burp: or native:")
            if ref.startswith("native:"):
                if t["selector"]:
                    raise ValueError("native reference cannot establish a GraphQL operation selector")
                try:
                    request_id = int(ref.removeprefix("native:"))
                except ValueError as exc:
                    raise ValueError("native tool ref must name a request ID") from exc
                row = self.db.execute("SELECT method,url FROM requests WHERE id=?", (request_id,)).fetchone()
                if not row or row["method"] != t["method"] or \
                        urlsplit(row["url"]).path != urlsplit(t["url"]).path or \
                        _origin(row["url"]) != _origin(t["url"]) or \
                        {k for k, _ in parse_qsl(urlsplit(row["url"]).query,
                                                 keep_blank_values=True)} != \
                        {k for k, _ in parse_qsl(urlsplit(t["url"]).query,
                                                 keep_blank_values=True)}:
                    raise ValueError("native request ID is absent or not the exact operation")
        data = self._artifacts(artifacts or [])
        if state in ("observed", "negative"):
            if not {"baseline", "test", "control"} <= set(data):
                raise ValueError("proof needs distinct baseline, test and control artifacts")
            hashes = [hashlib.sha256(data[r][1]).hexdigest() for r in ("baseline", "test", "control")]
            if len(set(hashes)) != 3 or marker.encode() not in data["baseline"][1] or \
                    marker.encode() not in data["test"][1] or marker.encode() in data["control"][1]:
                raise ValueError("baseline/test need the owned marker, control must differ and lack it")
            if _write_operation(t, case):
                if not {"before", "after"} <= set(data):
                    raise ValueError("write proof needs before/after owned-state readback")
                if state == "observed" and data["before"][1] == data["after"][1]:
                    raise ValueError("write proof needs a distinct before/after owned-state readback")
                if marker.encode() not in data["before"][1] + data["after"][1]:
                    raise ValueError("write readback must bind the owned marker")
        if impact in SENSITIVE and state == "observed" and not any(
                b"[redacted]" in blob.lower() for _, blob in data.values()):
            raise ValueError("sensitive proof needs an explicit [redacted] marker in evidence")
        if state in ("attempted", "observed", "negative"):
            host = urlsplit(t["url"]).hostname
            overall = self.db.execute("SELECT COALESCE(sum(requests_declared),0) FROM authz_events").fetchone()[0]
            host_used = sum(r["requests_declared"] for r in self.db.execute(
                "SELECT e.requests_declared,t.url FROM authz_events e "
                "JOIN authz_contexts c ON e.context_id=c.id "
                "JOIN authz_targets t ON c.target_id=t.id")
                if urlsplit(r["url"]).hostname == host)
            budget = self.grants["probe_budget"]
            write = _write_operation(t, case)
            prior = self.db.execute("SELECT variant,marker FROM authz_events WHERE context_id=? "
                                    "AND case_id=? AND state IN ('attempted','observed','negative')",
                                    (context_id, case)).fetchall()
            if write and any(p["marker"] == marker for p in prior) and not (
                    prior_attempt and state in ("observed", "negative") and requests == 0 and
                    all(p["marker"] != marker or p["variant"] == variant for p in prior) and
                    not any(r["state"] in ("observed", "negative") for r in self.db.execute(
                        "SELECT state FROM authz_events WHERE context_id=? AND case_id=? "
                        "AND variant=? AND marker=?", (context_id, case, variant, marker)))):
                raise ValueError("one write attempt per owned marker/resource; use a fresh disposable one")
            if case in ("ac-unauth", "ac-role", "ac-tenant", "ac-surface") and any(
                    p["marker"] == marker and p["variant"] != variant for p in prior):
                raise ValueError("one controlled variant per owned marker for this case")
            if not write and len({p["variant"] for p in prior} | {variant}) > budget["readonly_variants"]:
                raise ValueError("read-only case variant cap exhausted")
            if overall + requests > budget["requests"] or host_used + requests > budget["per_host"]:
                raise ValueError(f"declared authz budget exhausted for {host}; external traffic still "
                                 "needs manual reconciliation")
        # Stage/validate evidence before inserting an event. Stored copies are
        # content-addressed and cannot overwrite an existing different blob.
        dest = self.ctx.campaign.state_dir / "authz-evidence"
        if dest.is_symlink() or self.ctx.campaign.state_dir.is_symlink():
            raise ValueError("refusing a symlinked evidence store")
        kept = []
        for role, (source_path, blob) in data.items():
            sha = hashlib.sha256(blob).hexdigest()
            dest.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = dest / sha
            if path.is_symlink():
                raise ValueError("refusing a symlinked evidence file")
            if path.exists():
                if local_bytes(self.ctx.campaign.root, path) != blob:
                    raise ValueError("stored evidence changed")
            else:
                with path.open("xb") as stream:
                    stream.write(blob)
                path.chmod(0o600)
            kept.append((role, path.relative_to(self.ctx.campaign.root).as_posix(), sha,
                         len(blob), source_path))
        owner = owner or "hunt-access-control"
        cur = self.db.execute("INSERT INTO authz_events(context_id,case_id,variant,state,grant,"
                              "parent_id,impact,marker,proof_basis,policy_hash,facet_hash,"
                              "requests_declared,tool_refs,owner,root_key,related_cases,note,created) "
                              "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (context_id, case, variant, state, grant, parent_id, impact, marker,
                               proof_basis, self._policy_hash(), c["facets"], requests,
                               json.dumps(refs), owner, root_key, json.dumps(related_cases or []),
                               note, now()))
        for role, path, sha, size, source in kept:
            self.db.execute("INSERT INTO authz_artifacts VALUES(?,?,?,?,?,?)",
                            (cur.lastrowid, role, path, sha, size, source))
        self.db.commit()
        return {"event_id": cur.lastrowid, "context_id": context_id, "case": case,
                "state": state, "owner": owner, "root_key": root_key, "impact": impact,
                "artifacts": len(kept), "requests_declared": requests,
                "basis": "operator assertion with structural/integrity checks; no causal "
                         "finding confirmation or shared external budget enforcement",
                "finding_promoted": False, "executed": False}

    def verify(self):
        rows = self.db.execute("SELECT * FROM authz_events ORDER BY id").fetchall()
        invalid, artifact_errors = [], []
        for r in rows:
            try:
                c, t = self._context(r["context_id"])
                blobs = {}
                # Check each historic event, not only the latest in a variant.
                for a in self.db.execute("SELECT * FROM authz_artifacts WHERE event_id=?", (r["id"],)):
                    try:
                        blob = local_bytes(self.ctx.campaign.root, a["path"])
                        if len(blob) != a["bytes"] or hashlib.sha256(blob).hexdigest() != a["sha256"]:
                            raise ValueError("artifact tampered")
                        blobs[a["role"]] = blob
                    except (ValueError, OSError):
                        artifact_errors.append({"event": r["id"], "reason": "artifact missing/tampered"})
                issue = _proof_issue(r, t, blobs)
                if issue:
                    invalid.append({"event": r["id"], "reason": issue})
                if r["policy_hash"] != self._policy_hash() or r["facet_hash"] != c["facets"]:
                    invalid.append({"event": r["id"], "reason": "policy or context changed"})
                if r["parent_id"]:
                    parent = self.db.execute("SELECT * FROM authz_events WHERE id=?",
                                             (r["parent_id"],)).fetchone()
                    if not parent:
                        invalid.append({"event": r["id"], "reason": "parent missing"})
                    else:
                        pc, _ = self._context(parent["context_id"])
                        if self._event_state(pc, parent["case_id"], parent["variant"]) != (
                                "observed", parent["id"]):
                            invalid.append({"event": r["id"], "reason": "parent stale or superseded"})
            except (ValueError, OSError) as exc:
                invalid.append({"event": r["id"], "reason": str(exc)[:160]})
        issues = artifact_errors + invalid
        return {"verified": not issues, "artifact_integrity": not artifact_errors,
                "events_checked": len(rows), "invalid": issues[:100],
                "truncated_invalid": max(0, len(issues) - 100), "executed": False}

    def status(self, limit=100):
        plan = self.plan(limit=limit)
        totals = Counter()
        open_cases = []
        for target in plan["targets"]:
            for context in target["contexts"]:
                if context["superseded"]:
                    continue
                for card in context["cases"]:
                    state = card["state"] if card["state"] != "open" else card["readiness"]
                    if card["variants"] and card["state"] == "open":
                        # A successful one-off variant is reported, but does not
                        # close the whole case or its untried siblings.
                        for v in card["variants"]:
                            totals["variant:" + v["state"]] += 1
                    totals[state] += 1
                    # A clean negative applies to this exact variant only; it
                    # cannot silently close the remaining case/path/class work.
                    if state not in ("observed", "n-a") and len(open_cases) < 100:
                        pending = "variant-negative; other shapes unassessed" if state == "negative" else state
                        open_cases.append([target["target_id"], context["context_id"],
                                           card["case"], pending])
        coarse = []
        visible = {t["asset_id"] for t in plan["targets"]}
        for row in self.ctx.store.coverage():
            if row["bug_class"] in ("access-control", "mass-assignment") and row["status"] in (
                    "tested", "confirmed", "refuted", "n-a"):
                if row["asset_id"] not in visible or any(
                        t["asset_id"] == row["asset_id"] and any(
                            c["state"] not in ("observed", "n-a") or c["variants"] and
                            any(v["state"] not in ("observed", "n-a") for v in c["variants"])
                            for x in t["contexts"] if not x["superseded"]
                            for c in x["cases"] if c["class"] == row["bug_class"])
                        for t in plan["targets"]):
                    coarse.append([row["asset_id"], row["bug_class"], row["status"]])
        return {"totals": dict(totals), "open": open_cases, "coarse_conflicts": coarse[:100],
                "chain_rungs": [dict(r) for r in self.db.execute(
                    "SELECT id,case_id,state,parent_id,impact,owner FROM authz_events "
                    "WHERE case_id IN ('token-use','lateral','persistence') ORDER BY id DESC LIMIT 30")],
                "root_groups": [dict(r) for r in self.db.execute(
                    "SELECT root_key,COUNT(*) AS events FROM authz_events WHERE root_key<>'' "
                    "GROUP BY root_key ORDER BY events DESC LIMIT 30")],
                "visible_targets": plan["visible_targets"], "total_targets": plan["total_targets"],
                "truncated_targets": plan["truncated_targets"],
                "integrity": self.verify(), "basis": "sampled offline inventory; declared counts are "
                "not measured traffic; negative is one variant only; coarse coverage never "
                "closes open cases; unshown targets with coarse final status conflict by default",
                "executed": False}


def report_rows(ctx):
    result = AuthzLedger(ctx).status(limit=100)
    return {"totals": result["totals"], "open": result["open"][:30],
            "coarse": result["coarse_conflicts"], "total": result["total_targets"],
            "visible": result["visible_targets"], "truncated": result["truncated_targets"],
            "verified": result["integrity"]["verified"],
            "artifact_integrity": result["integrity"]["artifact_integrity"]}
