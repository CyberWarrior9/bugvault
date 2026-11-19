"""Shared offline business-invariant model behind the business-logic and race views.

Declarations are data: workflows, operations, resources and invariants with a finite,
typed predicate vocabulary evaluated over exact projections. No eval, template, SQL,
shell, regex execution or callback dispatch happens anywhere. Events are operator or
owned-lab evidence with hash-bound artifacts, source-qualified receipts and declared
accounting. Nothing here sends traffic, runs a synchronized sender or promotes a finding.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from .authz import SECRET_RE, digest
from .callbacks import local_bytes, valid_marker
from .campaign import HTTP_METHODS, OutOfScope, norm_host, validate_business_logic, validate_race
from .extract import endpoint_key, template_path
from .store import now

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS invariant_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workflow_definitions(
 id INTEGER PRIMARY KEY, wf_key TEXT NOT NULL, revision INTEGER NOT NULL, label TEXT NOT NULL,
 policy_source TEXT NOT NULL, policy_status TEXT NOT NULL, crown_jewel TEXT NOT NULL,
 states TEXT NOT NULL, edges TEXT NOT NULL, terminal TEXT NOT NULL, requires TEXT NOT NULL,
 definition_sha TEXT NOT NULL, created TEXT NOT NULL, UNIQUE(wf_key, revision));
CREATE TABLE IF NOT EXISTS workflow_operations(
 id INTEGER PRIMARY KEY, workflow_id INTEGER NOT NULL REFERENCES workflow_definitions(id),
 op_key TEXT NOT NULL, url TEXT NOT NULL, method TEXT NOT NULL, selector TEXT NOT NULL,
 fields TEXT NOT NULL, representation TEXT NOT NULL, version TEXT NOT NULL,
 transition TEXT NOT NULL, touches TEXT NOT NULL, shape_sha TEXT NOT NULL,
 in_scope INTEGER NOT NULL, UNIQUE(workflow_id, op_key));
CREATE TABLE IF NOT EXISTS workflow_resources(
 id INTEGER PRIMARY KEY, workflow_id INTEGER NOT NULL REFERENCES workflow_definitions(id),
 res_key TEXT NOT NULL, kind TEXT NOT NULL, owned INTEGER NOT NULL, shared INTEGER NOT NULL,
 disposable INTEGER NOT NULL, UNIQUE(workflow_id, res_key));
CREATE TABLE IF NOT EXISTS workflow_invariants(
 id INTEGER PRIMARY KEY, workflow_id INTEGER NOT NULL REFERENCES workflow_definitions(id),
 inv_key TEXT NOT NULL, rule TEXT NOT NULL, family TEXT NOT NULL, resource TEXT NOT NULL,
 predicate TEXT NOT NULL, oracle TEXT NOT NULL, deadline_seconds INTEGER NOT NULL,
 cleanup TEXT NOT NULL, definition_sha TEXT NOT NULL, UNIQUE(workflow_id, inv_key));
CREATE TABLE IF NOT EXISTS workflow_contexts(
 id INTEGER PRIMARY KEY, wf_key TEXT NOT NULL, account TEXT NOT NULL, role TEXT NOT NULL,
 tenant TEXT NOT NULL, session TEXT NOT NULL, state_label TEXT NOT NULL, capture_key TEXT NOT NULL,
 basis TEXT NOT NULL, observation_ids TEXT NOT NULL, facets TEXT NOT NULL, updated TEXT NOT NULL,
 UNIQUE(wf_key, account, role, tenant, session, state_label, capture_key));
CREATE TABLE IF NOT EXISTS race_scenarios(
 id INTEGER PRIMARY KEY, wf_key TEXT NOT NULL, inv_key TEXT NOT NULL,
 context_id INTEGER NOT NULL REFERENCES workflow_contexts(id), family TEXT NOT NULL,
 member_a TEXT NOT NULL, member_b TEXT NOT NULL, resource TEXT NOT NULL,
 order_matters INTEGER NOT NULL, source_event_id INTEGER, surviving_control TEXT NOT NULL,
 created TEXT NOT NULL, UNIQUE(wf_key, inv_key, context_id, family, member_a, member_b));
CREATE TABLE IF NOT EXISTS workflow_events(
 id INTEGER PRIMARY KEY, view TEXT NOT NULL,
 context_id INTEGER NOT NULL REFERENCES workflow_contexts(id), wf_key TEXT NOT NULL,
 inv_key TEXT NOT NULL, invariant_sha TEXT NOT NULL, case_id TEXT NOT NULL, variant TEXT NOT NULL,
 kind TEXT NOT NULL, scenario_id INTEGER REFERENCES race_scenarios(id), outcome TEXT NOT NULL,
 channel TEXT NOT NULL, basis TEXT NOT NULL, marker TEXT NOT NULL, control_marker TEXT NOT NULL,
 control TEXT NOT NULL, verdict TEXT NOT NULL, control_verdict TEXT NOT NULL, detail TEXT NOT NULL,
 receipts TEXT NOT NULL, objects INTEGER NOT NULL, object_ref TEXT NOT NULL,
 impact_claimed TEXT NOT NULL, impact_tier TEXT NOT NULL, attacker_gain TEXT NOT NULL,
 parent_id INTEGER REFERENCES workflow_events(id), root_key TEXT NOT NULL,
 policy_hash TEXT NOT NULL, facet_hash TEXT NOT NULL, note TEXT NOT NULL, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS workflow_events_case
 ON workflow_events(context_id, wf_key, inv_key, case_id, id);
CREATE TABLE IF NOT EXISTS workflow_artifacts(
 event_id INTEGER NOT NULL REFERENCES workflow_events(id), role TEXT NOT NULL, path TEXT NOT NULL,
 sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, source_path TEXT NOT NULL,
 PRIMARY KEY(event_id, role));
CREATE TABLE IF NOT EXISTS workflow_obligations(
 id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES workflow_events(id),
 host TEXT NOT NULL, kind TEXT NOT NULL, deadline TEXT NOT NULL, status TEXT NOT NULL,
 receipt TEXT NOT NULL, note TEXT NOT NULL, updated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workflow_stops(
 id INTEGER PRIMARY KEY, host TEXT NOT NULL, stop_kind TEXT NOT NULL,
 event_id INTEGER REFERENCES workflow_events(id), created TEXT NOT NULL,
 cleared TEXT NOT NULL DEFAULT '', clear_note TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS signal_profiles(
 host TEXT PRIMARY KEY, tells TEXT NOT NULL, http2 TEXT NOT NULL, score INTEGER NOT NULL,
 updated TEXT NOT NULL);
"""

IDENT = re.compile(r"[a-z0-9][a-z0-9._:-]{0,79}")
FIELD = re.compile(r"[A-Za-z0-9_.\[\]-]{1,100}")
POLICY_STATUS = ("documented", "owner-confirmed", "assumed", "declared", "inferred-observed", "unknown")
TRUSTED_POLICY = ("documented", "owner-confirmed", "declared")
ORACLES = ("ledger", "owner-trace", "persisted-state", "sandbox-receipt", "client-value")
CROWN_JEWELS = ("payout", "admin", "export", "entitlement", "money", "identity", "data", "none")
CROWN_RANK = {name: rank for rank, name in enumerate(CROWN_JEWELS)}
CONTROLS = ("revalidation", "domain-validation", "step-gating", "signature", "connection-identity",
            "atomicity", "idempotency", "serialization", "unknown")
OUTCOMES = ("attempted", "pending", "observed", "negative-for-variant", "blocked", "inconclusive",
            "skipped", "not-applicable")
TRAFFIC_OUTCOMES = ("attempted", "pending", "observed", "negative-for-variant")
NOTE_OUTCOMES = ("negative-for-variant", "blocked", "inconclusive", "skipped", "not-applicable")
REVIEW_OUTCOMES = ("inconclusive", "blocked", "skipped", "not-applicable")
CHANNELS = ("browser", "burp", "native", "scanner", "lab", "review")
LIVE_CHANNELS = ("browser", "burp", "native", "scanner")
CHANNEL_BASES = {"native": ("target-http",), "lab": ("owned-loopback",), "review": ("source-review",),
                 "browser": ("imported-burp-capture", "external-declared"),
                 "burp": ("imported-burp-capture", "external-declared"),
                 "scanner": ("imported-burp-capture", "external-declared")}
FACTS = ("prepared", "prefix_sent", "completed", "accepted", "queued", "worker_started",
         "committed", "effected", "settled", "compensated")
TIERS = ("T0", "T1", "T2", "T3", "T4")
PLAYS = ("P1-entitlement-action", "P2-artifact-account", "P3-value-effect", "closed-lead")
TERMINAL_KINDS = ("owned-write", "entitlement", "value-delta", "victim-read")
ROLES = ("baseline", "before", "after", "oracle", "control", "replay", "trace", "review",
          "owned-write", "readback", "value-delta", "victim-read", "redacted", "ui-control",
          "barrier-trace", "tool-attestation", "commit-trace", "receipt", "lab-rehearsal")
STOP_KINDS = ("challenge", "captcha", "rate-limit", "server-error", "degradation", "lockout",
              "incident", "real-user-data", "unapproved-host", "budget", "observer-lost",
              "uncontrolled-effect", "cleanup-unresolved")
CLEANUP_OUTCOMES = ("deleted", "aborted", "expired", "retained-by-owner", "reconciled",
                    "failed", "unverified")
CLEANUP_DONE = ("deleted", "aborted", "expired", "retained-by-owner", "reconciled")
PROJECTION_SOURCES = ("authoritative", "cache", "replica", "ui", "client")
PREDICATE_KEYS = {
    "allowed-transition": set(), "prerequisite-before-effect": {"prerequisite", "effect"},
    "at-most-count": {"limit"}, "bounded-quantity": {"min", "max", "unit"},
    "conservation-by-unit": {"currency", "exponent"}, "refund-capacity": {"currency", "exponent"},
    "intent-idempotent-effect": {"max_effects"}, "binding-equals": {"fields"},
    "terminal-state-consistency": {"exclusive"}, "version-current-at-effect": set()}
PROJECTION_KEYS = {
    "allowed-transition": {"from", "to"}, "prerequisite-before-effect": {"sequence"},
    "at-most-count": {"effects"}, "bounded-quantity": {"quantity", "unit"},
    "conservation-by-unit": {"opening", "inflows", "outflows", "closing"},
    "refund-capacity": {"captured", "refunds"}, "intent-idempotent-effect": {"intent_effects"},
    "binding-equals": {"approved", "executed"}, "terminal-state-consistency": {"final_states"},
    "version-current-at-effect": {"checked_version", "effect_version"}}
CONCURRENCY_RELEVANT = {"at-most-count", "bounded-quantity", "conservation-by-unit", "refund-capacity",
                        "intent-idempotent-effect", "terminal-state-consistency",
                        "version-current-at-effect"}
LIMITS = {"operations": 20, "invariants": 50, "edges": 100, "artifacts": 32, "states": 50,
          "resources": 50}
MAX_DECLARATION = 1_048_576
MAX_MINOR = 10 ** 15
EXACT = re.compile(r"-?\d{1,15}(?:\.\d{1,8})?")
TOUCHES = ("reads", "checks", "writes", "consumes", "publishes", "enqueues")
# Lineage-gated hints (plan 7.4). Deliberately not in findings.CHAIN_HINTS: those fire on
# same-host class coincidence, which these hints must never accept.
LINEAGE_HINTS = (
    ("business-logic", "access-control", "entitlement bypass -> action reserved to a role"),
    ("business-logic", "ato", "identity-trust violation -> account access"),
    ("race-conditions", "business-logic", "concurrency defeats the invariant the sequence family could not"),
    ("race-conditions", "ato", "concurrent use of a one-time auth artifact (reset token, OTP, invite)"),
    ("mass-assignment", "business-logic", "privileged field set -> entitlement granted"))
AUTH_ARTIFACT_KINDS = {"otp", "reset-token", "invite", "magic-link", "session", "verification-code"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def host_of(url: str) -> str:
    return norm_host(urlsplit(url).hostname or "")


def lab_host(host: str) -> bool:
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return host == "localhost" or host.endswith(".localhost")


def _text(value: Any, what: str, limit: int = 2000, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > limit or any(
            ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"{what} must be bounded text (at most {limit} characters)")
    if SECRET_RE.search(value.encode()):
        raise ValueError(f"{what} appears to contain a raw secret; redact it")
    if required and not value.strip():
        raise ValueError(f"{what} is required")
    return value


def _ident(value: Any, what: str) -> str:
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        raise ValueError(f"{what} must be an identifier matching {IDENT.pattern}")
    return value


def _strict(obj: Any, what: str, required=(), optional=()) -> Dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError(f"{what} must be an object")
    if any(not isinstance(key, str) for key in obj):
        raise ValueError(f"{what} must have string keys")
    unknown = set(obj) - set(required) - set(optional)
    missing = set(required) - set(obj)
    if unknown or missing:
        raise ValueError(f"{what} has unknown keys {sorted(unknown)} or misses {sorted(missing)}")
    return obj


def _int(value: Any, what: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:  # bool is rejected: type(True) is bool
        raise ValueError(f"{what} must be an integer in {low}..{high}")
    return value


def exact(value: Any, what: str) -> Decimal:
    """Exact integer or decimal string. Floats, booleans, NaN and infinity are refused."""
    if type(value) is int:
        if abs(value) > MAX_MINOR:
            raise ValueError(f"{what} overflows the supported magnitude")
        return Decimal(value)
    if isinstance(value, str) and EXACT.fullmatch(value):
        return Decimal(value)
    raise ValueError(f"{what} must be an integer or exact decimal string (no floats, NaN or infinity)")


def money(value: Any, currency: str, exponent: int, what: str) -> int:
    """Amount in checked integer minor units of exactly one declared currency."""
    _strict(value, what, required=("currency",), optional=("minor", "amount"))
    if ("minor" in value) == ("amount" in value):
        raise ValueError(f"{what} needs exactly one of minor or amount")
    if value["currency"] != currency:
        raise ValueError(f"{what} mixes currency {value['currency']!r} into {currency!r}")
    if "minor" in value:
        minor = value["minor"]
        if type(minor) is not int:
            raise ValueError(f"{what}.minor must be an integer of minor units")
    else:
        amount = exact(value["amount"], f"{what}.amount")
        scaled = amount * (Decimal(10) ** exponent)
        if scaled != scaled.to_integral_value():
            raise ValueError(f"{what}.amount has more decimal places than exponent {exponent}")
        minor = int(scaled)
    if abs(minor) > MAX_MINOR:
        raise ValueError(f"{what} overflows the supported magnitude")
    return minor


def _count(value: Any, what: str) -> int:
    return _int(value, what, 0, 1_000_000)


def _scalar(value: Any, what: str):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"{what} must be a string or integer (floats and booleans are refused)")
    if isinstance(value, str):
        _text(value, what, 200)
    return value


def evaluate(predicate: Dict[str, Any], workflow: Dict[str, Any], projections: Any,
             policy_status: str) -> Tuple[str, str]:
    """Deterministic comparison -> (satisfied|violated|unknown|not-applicable, reason)."""
    if policy_status not in TRUSTED_POLICY:
        return "unknown", "invariant policy is not documented or owner-confirmed"
    if projections is None:
        return "unknown", "no projections supplied"
    kind = predicate["type"]
    _strict(projections, "projections", optional=PROJECTION_KEYS[kind] | {"source"})
    source = projections.get("source", "authoritative")
    if source not in PROJECTION_SOURCES:
        raise ValueError(f"projection source must be one of {PROJECTION_SOURCES}")
    if source != "authoritative":
        return "unknown", f"{source} view is not authoritative state"
    missing = PROJECTION_KEYS[kind] - set(projections)
    if missing:
        return "unknown", f"missing projections {sorted(missing)}"
    p = projections
    states = set(workflow["states"])
    if kind == "allowed-transition":
        a, b = p["from"], p["to"]
        if a not in states or b not in states:
            raise ValueError("transition projections must use declared states")
        return ("satisfied" if [a, b] in workflow["edges"] else "violated"), f"{a} -> {b}"
    if kind == "prerequisite-before-effect":
        seq = p["sequence"]
        if not isinstance(seq, list) or len(seq) > 100 or any(not isinstance(s, str) for s in seq):
            raise ValueError("sequence must be a list of operation keys")
        if predicate["effect"] not in seq:
            return "not-applicable", "the protected effect did not occur"
        before = seq[:seq.index(predicate["effect"])]
        return ("satisfied" if predicate["prerequisite"] in before else "violated"), "effect order"
    if kind == "at-most-count":
        effects = _count(p["effects"], "effects")
        return ("satisfied" if effects <= predicate["limit"] else "violated"), \
            f"{effects} effects, limit {predicate['limit']}"
    if kind == "bounded-quantity":
        if p["unit"] != predicate["unit"]:
            raise ValueError(f"quantity unit {p['unit']!r} differs from declared {predicate['unit']!r}")
        quantity = exact(p["quantity"], "quantity")
        ok = exact(predicate["min"], "min") <= quantity <= exact(predicate["max"], "max")
        return ("satisfied" if ok else "violated"), f"quantity {quantity}"
    if kind in ("conservation-by-unit", "refund-capacity"):
        cur, exp = predicate["currency"], predicate["exponent"]
        if kind == "conservation-by-unit":
            for key in ("inflows", "outflows"):
                if not isinstance(p[key], list) or len(p[key]) > 100:
                    raise ValueError(f"{key} must be a list of at most 100 amounts")
            opening = money(p["opening"], cur, exp, "opening")
            closing = money(p["closing"], cur, exp, "closing")
            flow = sum(money(v, cur, exp, "inflow") for v in p["inflows"]) - \
                sum(money(v, cur, exp, "outflow") for v in p["outflows"])
            return ("satisfied" if opening + flow == closing else "violated"), \
                f"expected {opening + flow} minor units, closing {closing}"
        if not isinstance(p["refunds"], list) or len(p["refunds"]) > 100:
            raise ValueError("refunds must be a list of at most 100 amounts")
        captured = money(p["captured"], cur, exp, "captured")
        refunded = sum(money(v, cur, exp, "refund") for v in p["refunds"])
        return ("satisfied" if refunded <= captured else "violated"), \
            f"{refunded} refunded of {captured} captured minor units"
    if kind == "intent-idempotent-effect":
        effects = _count(p["intent_effects"], "intent_effects")
        return ("satisfied" if effects <= predicate["max_effects"] else "violated"), \
            f"{effects} effects for one intent"
    if kind == "binding-equals":
        fields = set(predicate["fields"])
        for key in ("approved", "executed"):
            if not isinstance(p[key], dict) or set(p[key]) != fields:
                raise ValueError(f"{key} must bind exactly the declared fields {sorted(fields)}")
        changed = sorted(f for f in fields if _scalar(p["approved"][f], f) != _scalar(p["executed"][f], f))
        return ("violated" if changed else "satisfied"), f"changed {changed}"
    if kind == "terminal-state-consistency":
        final = p["final_states"]
        if not isinstance(final, list) or any(s not in states for s in final):
            raise ValueError("final_states must list declared states")
        clash = [pair for pair in predicate["exclusive"] if pair[0] in final and pair[1] in final]
        return ("violated" if clash else "satisfied"), f"exclusive clash {clash}"
    checked = _int(p["checked_version"], "checked_version", 0, 10 ** 12)
    effect = _int(p["effect_version"], "effect_version", 0, 10 ** 12)
    return ("satisfied" if checked == effect else "violated"), f"checked v{checked}, effected v{effect}"


def _parse_predicate(raw: Any, states, op_keys) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("type") not in PREDICATE_KEYS:
        raise ValueError(f"predicate must be an object with type in {sorted(PREDICATE_KEYS)}; "
                         "free-text or expression rules are not executable")
    kind = raw["type"]
    _strict(raw, "predicate", required={"type"} | PREDICATE_KEYS[kind])
    out = {"type": kind}
    if kind == "prerequisite-before-effect":
        for key in ("prerequisite", "effect"):
            if raw[key] not in op_keys:
                raise ValueError(f"predicate {key} must name a declared operation")
            out[key] = raw[key]
    elif kind == "at-most-count":
        out["limit"] = _int(raw["limit"], "limit", 0, 1000)
    elif kind == "bounded-quantity":
        out.update({"min": raw["min"], "max": raw["max"], "unit": _ident(raw["unit"], "unit")})
        if exact(raw["min"], "min") > exact(raw["max"], "max"):
            raise ValueError("bounded-quantity min exceeds max")
    elif kind in ("conservation-by-unit", "refund-capacity"):
        if not isinstance(raw["currency"], str) or not re.fullmatch(r"[A-Z]{3}", raw["currency"]):
            raise ValueError("currency must be a three-letter code")
        out.update({"currency": raw["currency"], "exponent": _int(raw["exponent"], "exponent", 0, 8)})
    elif kind == "intent-idempotent-effect":
        out["max_effects"] = _int(raw["max_effects"], "max_effects", 1, 10)
    elif kind == "binding-equals":
        fields = raw["fields"]
        if (not isinstance(fields, list) or not 1 <= len(fields) <= 10 or
                any(not isinstance(f, str) for f in fields) or len(set(fields)) != len(fields)):
            raise ValueError("binding-equals needs 1..10 unique fields")
        out["fields"] = [_ident(f, "binding field") for f in fields]
    elif kind == "terminal-state-consistency":
        pairs = raw["exclusive"]
        if not isinstance(pairs, list) or not 1 <= len(pairs) <= 20 or any(
                not isinstance(p, list) or len(p) != 2 or p[0] not in states or p[1] not in states
                for p in pairs):
            raise ValueError("exclusive must list 1..20 pairs of declared states")
        out["exclusive"] = [list(p) for p in pairs]
    return out


def _acyclic(pairs) -> bool:
    graph = defaultdict(list)
    for a, b in pairs:
        graph[a].append(b)
    state: Dict[str, int] = {}

    def visit(node) -> bool:
        if state.get(node) == 1:
            return False
        if state.get(node) == 2:
            return True
        state[node] = 1
        if not all(visit(n) for n in graph[node]):
            return False
        state[node] = 2
        return True

    return all(visit(n) for n in list(graph))


def parse_declaration(data: Any, scope) -> Dict[str, Any]:
    """Validate a bounded schema-1 workflow declaration completely before any write."""
    _strict(data, "declaration", required=("schema", "workflow", "operations", "resources", "invariants"),
            optional=("lab_contexts",))
    if type(data["schema"]) is not int or data["schema"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported declaration schema {data['schema']!r}; this build reads {SCHEMA_VERSION}")
    wf = _strict(data["workflow"], "workflow", required=("key", "revision", "policy_source", "policy_status",
                                                         "states", "edges"),
                 optional=("label", "crown_jewel", "terminal", "requires"))
    states = wf["states"]
    if not isinstance(states, list) or not 1 <= len(states) <= LIMITS["states"] or \
            any(not isinstance(s, str) for s in states) or len(set(states)) != len(states):
        raise ValueError(f"states must be 1..{LIMITS['states']} unique identifiers")
    for s in states:
        _ident(s, "state")
    edges = wf["edges"]
    if not isinstance(edges, list) or len(edges) > LIMITS["edges"] or any(
            not isinstance(e, list) or len(e) != 2 or e[0] not in states or e[1] not in states for e in edges):
        raise ValueError(f"edges must be at most {LIMITS['edges']} [from, to] pairs of declared states")
    terminal = wf.get("terminal", [])
    if not isinstance(terminal, list) or any(s not in states for s in terminal):
        raise ValueError("terminal must list declared states")
    if wf["policy_status"] not in POLICY_STATUS:
        raise ValueError(f"policy_status must be one of {POLICY_STATUS}")
    crown = wf.get("crown_jewel", "none")
    if crown not in CROWN_JEWELS:
        raise ValueError(f"crown_jewel must be one of {CROWN_JEWELS}")
    workflow = {"key": _ident(wf["key"], "workflow key"),
                "revision": _int(wf["revision"], "revision", 1, 10_000),
                "label": _text(wf.get("label", ""), "label", 200),
                "policy_source": _text(wf["policy_source"], "policy_source", 500, required=True),
                "policy_status": wf["policy_status"], "crown_jewel": crown,
                "states": list(states), "edges": [list(e) for e in edges], "terminal": list(terminal)}
    resources = data["resources"]
    if not isinstance(resources, list) or len(resources) > LIMITS["resources"]:
        raise ValueError(f"resources must be a list of at most {LIMITS['resources']}")
    res = []
    for item in resources:
        r = _strict(item, "resource", required=("key", "kind"), optional=("owned", "shared", "disposable"))
        flags = {k: r.get(k, False) for k in ("owned", "shared", "disposable")}
        if any(type(v) is not bool for v in flags.values()):
            raise ValueError("resource owned/shared/disposable must be booleans")
        res.append({"key": _ident(r["key"], "resource key"), "kind": _ident(r["kind"], "resource kind"),
                    **flags})
    res_keys = {r["key"] for r in res}
    if len(res_keys) != len(res):
        raise ValueError("resource keys must be unique")
    ops_raw = data["operations"]
    if not isinstance(ops_raw, list) or not 1 <= len(ops_raw) <= LIMITS["operations"]:
        raise ValueError(f"operations must list 1..{LIMITS['operations']} operations")
    ops, shapes = [], set()
    for item in ops_raw:
        o = _strict(item, "operation", required=("key", "url", "method"),
                    optional=("selector", "fields", "representation", "version", "transition", *TOUCHES))
        url = o["url"]
        parts = urlsplit(url) if isinstance(url, str) else None
        if not parts or parts.scheme not in ("http", "https", "ws", "wss") or not parts.hostname or \
                parts.username is not None or len(url) > 2000:
            raise ValueError("operation url must be a plain http(s)/ws(s) URL")
        method = o["method"].upper() if isinstance(o["method"], str) else ""
        if method not in HTTP_METHODS and method != "UNKNOWN":
            raise ValueError("operation method must be an HTTP method or UNKNOWN")
        fields = o.get("fields", [])
        if not isinstance(fields, list) or len(fields) > 30 or any(
                not isinstance(f, str) or not FIELD.fullmatch(f) for f in fields):
            raise ValueError("operation fields must be at most 30 field names")
        transition = o.get("transition", [])
        if transition and (not isinstance(transition, list) or len(transition) != 2 or
                           any(s not in states for s in transition)):
            raise ValueError("operation transition must be [from, to] declared states")
        touches = {}
        for key in TOUCHES:
            refs = o.get(key, [])
            if not isinstance(refs, list) or any(r not in res_keys for r in refs):
                raise ValueError(f"operation {key} must reference declared resources")
            touches[key] = list(refs)
        selector = _text(o.get("selector", ""), "selector", 200)
        representation = _text(o.get("representation", ""), "representation", 100)
        version = _text(o.get("version", ""), "version", 40)
        query = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
        shape = digest({"scheme": parts.scheme, "host": norm_host(parts.hostname),
                        "port": parts.port, "path": parts.path or "/", "query": query,
                        "method": method, "selector": selector, "fields": sorted(fields),
                        "representation": representation, "version": version})
        if shape in shapes:
            raise ValueError("two operations share one exact shape; declare it once")
        shapes.add(shape)
        ops.append({"key": _ident(o["key"], "operation key"), "url": url, "method": method,
                    "selector": selector, "fields": list(fields), "representation": representation,
                    "version": version, "transition": list(transition), "touches": touches,
                    "shape_sha": shape, "in_scope": scope.is_in(url)})
    op_keys = {o["key"] for o in ops}
    if len(op_keys) != len(ops):
        raise ValueError("operation keys must be unique")
    requires = wf.get("requires", [])
    if not isinstance(requires, list) or len(requires) > LIMITS["edges"] or any(
            not isinstance(p, list) or len(p) != 2 or p[0] not in op_keys or p[1] not in op_keys
            for p in requires):
        raise ValueError("requires must list [prerequisite, operation] pairs of declared operations")
    if not _acyclic(requires):
        raise ValueError("requires contains a cycle in required ordering")
    workflow["requires"] = [list(p) for p in requires]
    inv_raw = data["invariants"]
    if not isinstance(inv_raw, list) or not 1 <= len(inv_raw) <= LIMITS["invariants"]:
        raise ValueError(f"invariants must list 1..{LIMITS['invariants']} invariants")
    invariants = []
    for item in inv_raw:
        i = _strict(item, "invariant", required=("key", "rule", "family", "resource", "oracle", "predicate"),
                    optional=("deadline_seconds", "cleanup"))
        if not isinstance(i["family"], str) or not re.fullmatch(r"BL-(?:0[1-9]|1[0-8])", i["family"]):
            raise ValueError("invariant family must be a BL-01..BL-18 case family")
        if i["resource"] not in res_keys:
            raise ValueError("invariant resource must be a declared resource")
        if i["oracle"] not in ORACLES:
            raise ValueError(f"oracle must be one of {ORACLES}")
        invariants.append({"key": _ident(i["key"], "invariant key"),
                           "rule": _text(i["rule"], "rule", 1000, required=True),
                           "family": i["family"], "resource": i["resource"], "oracle": i["oracle"],
                           "predicate": _parse_predicate(i["predicate"], states, op_keys),
                           "deadline_seconds": _int(i.get("deadline_seconds", 300), "deadline_seconds",
                                                    1, 86_400),
                           "cleanup": _text(i.get("cleanup", ""), "cleanup", 500)})
    if len({i["key"] for i in invariants}) != len(invariants):
        raise ValueError("invariant keys must be unique")
    lab_contexts = data.get("lab_contexts", [])
    if not isinstance(lab_contexts, list) or len(lab_contexts) > 10:
        raise ValueError("lab_contexts must be a list of at most 10 owned lab identities")
    contexts = []
    for item in lab_contexts:
        c = _strict(item, "lab context", required=("account", "role", "tenant", "session"),
                    optional=("state",))
        if not all(lab_host(host_of(o["url"])) for o in ops):
            raise ValueError("declared lab contexts require exclusively loopback operations")
        contexts.append({"account": _ident(c["account"], "account"),
                         "role": _ident(c["role"], "role"), "tenant": _ident(c["tenant"], "tenant"),
                         "session": _ident(c["session"], "session"),
                         "state": _ident(c.get("state", states[0]), "state")})
        if contexts[-1]["state"] not in states:
            raise ValueError("lab context state must be a declared state")
    if len({tuple(c.values()) for c in contexts}) != len(contexts):
        raise ValueError("lab contexts must be unique")
    normalized = {"workflow": workflow, "operations": ops, "resources": res, "invariants": invariants,
                  "lab_contexts": contexts}
    normalized["sha"] = digest(normalized)
    for inv in invariants:
        inv["sha"] = digest({"invariant": inv, "states": states, "edges": workflow["edges"],
                             "policy": [workflow["policy_status"], workflow["policy_source"]]})
    return normalized


def read_json_file(path) -> Any:
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_DECLARATION + 1)
    if len(data) > MAX_DECLARATION:
        raise ValueError("JSON input exceeds one mebibyte")
    return json.loads(data)


class Model:
    """Storage, readiness, recording and verification shared by both views."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.db = ctx.store.db
        row = None
        try:
            row = self.db.execute("SELECT value FROM invariant_meta WHERE key='schema_version'").fetchone()
        except Exception:  # table absent on a legacy campaign
            row = None
        if row is not None and int(row["value"]) > SCHEMA_VERSION:
            raise ValueError("this campaign's invariant schema is newer than this build; refusing to open")
        self.db.executescript(SCHEMA)
        self.db.execute("INSERT OR IGNORE INTO invariant_meta VALUES('schema_version', ?)",
                        (str(SCHEMA_VERSION),))
        self.db.commit()
        self.logic_config = validate_business_logic(ctx.campaign.raw.get("business_logic", {}))
        self.race_config = validate_race(ctx.campaign.raw.get("race", {}))

    # ------------------------------------------------------------------ identity
    def policy_hash(self) -> str:
        raw = self.ctx.campaign.raw
        lc, rc = self.logic_config, self.race_config
        return digest({"scope": [raw.get(k) for k in ("in_scope", "out_of_scope", "excluded_bug_classes",
                                                       "rules", "program_url")],
                       "mode": self.ctx.policy.mode, "methods": sorted(self.ctx.policy.allowed_methods),
                       "limits": [self.ctx.policy.max_requests, self.ctx.policy.max_campaign_requests,
                                  self.ctx.policy.max_rps],
                       "logic": [lc["policy_reviewed"], sorted(lc["families"]), sorted(lc["permits"]),
                                  sorted(lc["owned_accounts"]), lc["budget"], lc["retention_days"]],
                       "race": [rc["policy_reviewed"], sorted(rc["families"]), rc["burst"]]})

    def declare(self, data) -> Dict[str, Any]:
        norm = parse_declaration(data, self.ctx.scope)
        wf = norm["workflow"]
        row = self.db.execute("SELECT id,definition_sha FROM workflow_definitions WHERE wf_key=? AND "
                              "revision=?", (wf["key"], wf["revision"])).fetchone()
        if row:
            if row["definition_sha"] != norm["sha"]:
                raise ValueError(f"{wf['key']} revision {wf['revision']} already has different content; "
                                 "declare a new revision")
            return {"workflow": wf["key"], "revision": wf["revision"], "unchanged": True,
                    "executed": False}
        latest = self.db.execute("SELECT max(revision) FROM workflow_definitions WHERE wf_key=?",
                                 (wf["key"],)).fetchone()[0]
        if latest is not None and wf["revision"] < latest:
            raise ValueError("a new revision must be greater than the latest declared revision")
        self.db.commit()
        try:
            wid = self.db.execute(
                "INSERT INTO workflow_definitions(wf_key,revision,label,policy_source,policy_status,"
                "crown_jewel,states,edges,terminal,requires,definition_sha,created) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (wf["key"], wf["revision"], wf["label"], wf["policy_source"], wf["policy_status"],
                 wf["crown_jewel"], json.dumps(wf["states"]), json.dumps(wf["edges"]),
                 json.dumps(wf["terminal"]), json.dumps(wf["requires"]), norm["sha"], now())).lastrowid
            for o in norm["operations"]:
                self.db.execute(
                    "INSERT INTO workflow_operations(workflow_id,op_key,url,method,selector,fields,"
                    "representation,version,transition,touches,shape_sha,in_scope) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (wid, o["key"], o["url"], o["method"], o["selector"], json.dumps(o["fields"]),
                     o["representation"], o["version"], json.dumps(o["transition"]),
                     json.dumps(o["touches"]), o["shape_sha"], int(o["in_scope"])))
            for r in norm["resources"]:
                self.db.execute("INSERT INTO workflow_resources(workflow_id,res_key,kind,owned,shared,"
                                "disposable) VALUES(?,?,?,?,?,?)",
                                (wid, r["key"], r["kind"], int(r["owned"]), int(r["shared"]),
                                 int(r["disposable"])))
            for i in norm["invariants"]:
                self.db.execute(
                    "INSERT INTO workflow_invariants(workflow_id,inv_key,rule,family,resource,predicate,"
                    "oracle,deadline_seconds,cleanup,definition_sha) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (wid, i["key"], i["rule"], i["family"], i["resource"], json.dumps(i["predicate"]),
                     i["oracle"], i["deadline_seconds"], i["cleanup"], i["sha"]))
            for c in norm["lab_contexts"]:
                self.db.execute("INSERT OR IGNORE INTO workflow_contexts(wf_key,account,role,tenant,session,"
                                "state_label,capture_key,basis,observation_ids,facets,updated) "
                                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                                (wf["key"], c["account"], c["role"], c["tenant"], c["session"],
                                 c["state"], f"lab:{wf['revision']}:{c['account']}:{c['session']}",
                                 "owned-loopback-declared", "[]", norm["sha"], now()))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        gaps = [o["key"] for o in norm["operations"] if not o["in_scope"]]
        return {"workflow": wf["key"], "revision": wf["revision"], "workflow_id": wid,
                "operations": len(norm["operations"]), "invariants": len(norm["invariants"]),
                "out_of_scope_gaps": gaps, "unchanged": False,
                "basis": "declared policy model, not evidence that the server follows it; "
                         "out-of-scope operations stay gaps and are never contacted",
                "executed": False}

    # ------------------------------------------------------------------ lookups
    def workflow(self, wf_key: str) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM workflow_definitions WHERE wf_key=? ORDER BY revision DESC "
                              "LIMIT 1", (wf_key,)).fetchone()
        if not row:
            return None
        wf = dict(row)
        for key in ("states", "edges", "terminal", "requires"):
            wf[key] = json.loads(wf[key])
        return wf

    def workflows(self) -> List[Dict[str, Any]]:
        keys = [r["wf_key"] for r in self.db.execute(
            "SELECT DISTINCT wf_key FROM workflow_definitions ORDER BY wf_key")]
        return [self.workflow(k) for k in keys]

    def operations(self, workflow_id: int) -> List[Dict[str, Any]]:
        out = []
        for r in self.db.execute("SELECT * FROM workflow_operations WHERE workflow_id=? ORDER BY id",
                                 (workflow_id,)):
            op = dict(r)
            for key in ("fields", "transition", "touches"):
                op[key] = json.loads(op[key])
            out.append(op)
        return out

    def resources(self, workflow_id: int) -> Dict[str, Dict[str, Any]]:
        return {r["res_key"]: dict(r) for r in self.db.execute(
            "SELECT * FROM workflow_resources WHERE workflow_id=?", (workflow_id,))}

    def invariants(self, workflow_id: int) -> List[Dict[str, Any]]:
        out = []
        for r in self.db.execute("SELECT * FROM workflow_invariants WHERE workflow_id=? ORDER BY id",
                                 (workflow_id,)):
            inv = dict(r)
            inv["predicate"] = json.loads(inv["predicate"])
            out.append(inv)
        return out

    def current_invariant(self, wf_key: str, inv_key: str):
        wf = self.workflow(wf_key)
        if not wf:
            return None, None
        inv = next((i for i in self.invariants(wf["id"]) if i["inv_key"] == inv_key), None)
        return wf, inv

    def context(self, context_id) -> Dict[str, Any]:
        if type(context_id) is not int or context_id < 1:
            raise ValueError("context must be a positive integer ID")
        row = self.db.execute("SELECT * FROM workflow_contexts WHERE id=?", (context_id,)).fetchone()
        if not row:
            raise ValueError("unknown workflow context; run sync after declaring the workflow")
        return dict(row)

    def contexts(self, wf_key: str) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM workflow_contexts WHERE wf_key=? ORDER BY id", (wf_key,))]

    # ------------------------------------------------------------------ contexts
    def sync_contexts(self) -> Dict[str, int]:
        """Group captures of declared operations into exact contexts; unknown labels stay isolated."""
        stats = Counter()
        for wf in self.workflows():
            groups = defaultdict(list)
            for op in self.operations(wf["id"]):
                if not op["in_scope"] or not self.ctx.scope.is_in(op["url"]):
                    continue
                asset = self.ctx.store.find_asset("endpoint", endpoint_key(op["url"]))
                if not asset:
                    continue
                declared_path = urlsplit(op["url"]).path or "/"
                query_names = sorted({k for k, _ in parse_qsl(urlsplit(op["url"]).query,
                                                                keep_blank_values=True)})
                for o in self.ctx.store.observations(asset["id"])[-500:]:
                    if op["method"] != "UNKNOWN" and (o.get("method") or "").upper() != op["method"]:
                        continue
                    c = o.get("context") or {}
                    p = o.get("params") or {}
                    if not isinstance(c, dict) or not isinstance(p, dict):
                        continue
                    observed_path = c.get("path")
                    if observed_path and (template_path(observed_path) if "{id}" in declared_path else
                                          observed_path) != declared_path:
                        continue
                    observed_query = p.get("query")
                    if observed_query is not None and (not isinstance(observed_query, list) or
                                                       any(not isinstance(n, str) for n in observed_query)):
                        continue
                    if query_names and observed_query is None or observed_query is not None and \
                            sorted(set(observed_query)) != query_names:
                        continue
                    body_names = p.get("body") or []
                    if not isinstance(body_names, list) or any(not isinstance(n, str) for n in body_names):
                        continue
                    if op["fields"] and not set(op["fields"]) <= (set(observed_query or []) |
                                                               set(body_names)):
                        continue
                    meta = c.get("csrf_meta") or {}
                    if not isinstance(meta, dict):
                        continue
                    if op["selector"] and op["selector"] not in meta.get("graphql_operations", []):
                        continue
                    if op["representation"] and meta.get("content_type") != op["representation"].lower():
                        continue
                    if op["version"] and c.get("version") != op["version"]:
                        continue
                    labels = tuple(str(v)[:200] for v in (
                        o.get("account") or "unknown", c.get("role") or "unknown",
                        c.get("tenant") or "unknown", c.get("session") or "",
                        c.get("workflow_state") or ""))
                    key = (*labels, f"observation:{o['id']}" if "unknown" in labels[:3] else "")
                    groups[key].append(o)
            for key, obs in groups.items():
                facets = digest([(o["id"], o.get("params"), o.get("context"))
                                 for o in sorted(obs, key=lambda o: o["id"])])
                ids = json.dumps(sorted(o["id"] for o in obs))
                basis = "captured" if obs else "declared"
                row = self.db.execute(
                    "SELECT id,facets FROM workflow_contexts WHERE wf_key=? AND account=? AND role=? AND "
                    "tenant=? AND session=? AND state_label=? AND capture_key=?",
                    (wf["wf_key"], *key)).fetchone()
                if row:
                    if row["facets"] != facets:
                        self.db.execute("UPDATE workflow_contexts SET facets=?,observation_ids=?,basis=?,"
                                        "updated=? WHERE id=?", (facets, ids, basis, now(), row["id"]))
                        stats["contexts_reopened"] += 1
                    continue
                self.db.execute(
                    "INSERT INTO workflow_contexts(wf_key,account,role,tenant,session,state_label,"
                    "capture_key,basis,observation_ids,facets,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (wf["wf_key"], *key, basis, ids, facets, now()))
                stats["contexts_added"] += 1
        self.db.commit()
        return dict(stats)

    # ------------------------------------------------------------------ gates
    def active_stop(self, host: str) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM workflow_stops WHERE host=? AND cleared='' "
                              "ORDER BY id DESC LIMIT 1", (host,)).fetchone()
        return dict(row) if row else None

    def usage(self) -> Dict[str, Any]:
        """Source-qualified accounting: each receipt counts once across every event."""
        native, imported, lab, external = set(), set(), set(), {}
        hosts = Counter()
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='race_attestations'").fetchone():
            for r in self.db.execute("SELECT label,requests,host FROM race_attestations"):
                external[r["label"]] = r["requests"]
                hosts[r["host"]] += r["requests"]
        for r in self.db.execute("SELECT receipts FROM workflow_events"):
            for receipt in json.loads(r["receipts"]):
                basis = receipt["basis"]
                if basis == "external-declared":
                    if receipt["label"] not in external:
                        external[receipt["label"]] = receipt["requests"]
                        hosts[receipt["host"]] += receipt["requests"]
                    continue
                bucket = {"target-http": native, "imported-burp-capture": imported,
                          "owned-loopback": lab}[basis]
                if receipt["request_id"] not in bucket:
                    bucket.add(receipt["request_id"])
                    if basis == "target-http":
                        hosts[receipt["host"]] += 1
        objects = self.db.execute("SELECT COALESCE(sum(objects),0) FROM workflow_events WHERE "
                                  "channel IN ('browser','burp','native','scanner')").fetchone()[0]
        return {"native_measured": len(native), "external_declared": sum(external.values()),
                "imported_historical": len(imported), "lab": len(lab), "objects": objects,
                "hosts": hosts,
                "basis": "native counts cite stored target-http rows once; external counts are "
                         "operator declarations; imported captures and lab traffic are labelled and "
                         "not charged. The ledger cannot intercept send, Burp or a browser."}

    def live_gate(self, view: str, family: str, family_modes, context, wf, inv, ops,
                  concurrent=False, parallelism=None, channel=None, prepaid=False) -> Tuple[str, str]:
        """Readiness of one live attempt. Reasons name policy versus capability blockers."""
        hosts = {host_of(o["url"]) for o in ops}
        for host in sorted(hosts):
            stop = self.active_stop(host)
            if stop:
                return "blocked", f"host {host} stopped after {stop['stop_kind']}; resolve, then logic resume"
        need = "C-P" if concurrent else "C-S"
        if need not in family_modes:
            return "lab-only", f"{family} is review/owned-lab only ({'/'.join(family_modes)})"
        if concurrent and channel not in (None, "burp"):
            return "capability-blocked", ("no scope-enforced synchronized sender exists (plan M5-M6); "
                                           "only operator-run Burp groups can be recorded")
        if self.ctx.policy.mode == "passive":
            return "policy-blocked", "campaign mode is passive"
        outside = [o["op_key"] for o in ops if not o["in_scope"] or
                   not self.ctx.scope.is_in(o["url"])]
        if outside:
            return "policy-blocked", f"operations {outside} are outside the recorded scope (gaps)"
        bad = sorted({o["method"] for o in ops if o["method"] == "UNKNOWN" or
                      o["method"] not in self.ctx.policy.allowed_methods})
        if bad:
            return "policy-blocked", f"policy.allowed_methods does not grant {bad}"
        config = self.logic_config if view == "logic" else self.race_config
        section = "business_logic" if view == "logic" else "race"
        if not str(self.ctx.campaign.raw.get("program_url") or "").strip() or not config["policy_reviewed"]:
            return "policy-blocked", (f"record program_url and {section}.policy_reviewed from the "
                                      "program's published rules")
        if family not in config["families"]:
            return "policy-blocked", f"{section}.families does not include {family}"
        if context["basis"] != "captured":
            return "waiting-capture", "capture the real workflow for this context"
        if "unknown" in (context["account"], context["role"], context["tenant"]):
            return "waiting-prerequisite", "label account/role/tenant on the capture"
        if context["account"] not in self.logic_config["owned_accounts"]:
            return "policy-blocked", "only operator-owned test account labels may be used live"
        if wf["policy_status"] not in TRUSTED_POLICY:
            return "policy-blocked", "invariant policy unresolved; record the documented or owner-confirmed rule"
        if inv["oracle"] == "client-value":
            return "waiting-prerequisite", "oracle-untrusted: name an authoritative ledger, trace or state readback"
        budget = self.logic_config["budget"]
        if budget["requests"] == 0:
            return "policy-blocked", "business_logic.budget allows no live traffic"
        used = self.usage()
        if not prepaid and (used["native_measured"] + used["external_declared"] >= budget["requests"] or any(
                used["hosts"][h] >= budget["per_host"] for h in hosts)):
            return "policy-blocked", "shared business_logic budget exhausted"
        if concurrent:
            burst = self.race_config["burst"]
            if burst["max_parallelism"] == 0:
                return "policy-blocked", "race.burst allows no concurrent groups"
            if parallelism is not None and parallelism > burst["max_parallelism"]:
                return "policy-blocked", f"parallelism {parallelism} exceeds race.burst.max_parallelism"
            return "ready", "operator-run Burp group inside recorded scope and burst; manual external accounting"
        return "ready", "inside recorded scope, methods, families and shared budget"

    # ------------------------------------------------------------------ evidence helpers
    def artifacts(self, items) -> Dict[str, Tuple[str, bytes]]:
        if items is None:
            items = []
        if not isinstance(items, list) or len(items) > LIMITS["artifacts"]:
            raise ValueError(f"at most {LIMITS['artifacts']} artifacts")
        out, total = {}, 0
        for item in items:
            if not isinstance(item, str):
                raise ValueError("artifacts are ROLE=PATH strings")
            role, sep, path = item.partition("=")
            if not sep or role not in ROLES or role in out:
                raise ValueError(f"artifacts need unique ROLE=PATH with role in {list(ROLES)}")
            if (not path or len(path) > 300 or Path(path).is_absolute() or ".." in Path(path).parts
                    or SECRET_RE.search(path.encode())):
                raise ValueError("artifact must be a short campaign-relative redacted path")
            source = self.ctx.campaign.root / path
            if source.is_symlink():
                raise ValueError("artifact paths must not be symbolic links")
            data = local_bytes(self.ctx.campaign.root, path)
            if SECRET_RE.search(data):
                raise ValueError("artifact appears to contain an unredacted secret")
            total += len(data)
            if total > 25 * 1024 * 1024:
                raise ValueError("artifacts exceed 25 MiB per event")
            out[role] = (path, data)
        return out

    def keep(self, data) -> List[Tuple[str, str, str, int, str]]:
        dest = self.ctx.campaign.state_dir / "invariant-evidence"
        if dest.is_symlink() or self.ctx.campaign.state_dir.is_symlink():
            raise ValueError("refusing a symlinked evidence store")
        kept = []
        for role, (source, blob) in data.items():
            sha = _sha(blob)
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
            kept.append((role, path.relative_to(self.ctx.campaign.root).as_posix(), sha, len(blob), source))
        return kept

    def blobs(self, event_id: int) -> Optional[Dict[str, bytes]]:
        out = {}
        for a in self.db.execute("SELECT * FROM workflow_artifacts WHERE event_id=?", (event_id,)):
            try:
                data = local_bytes(self.ctx.campaign.root, a["path"])
            except (ValueError, OSError):
                return None
            if len(data) != a["bytes"] or _sha(data) != a["sha256"]:
                return None
            out[a["role"]] = data
        return out

    def receipts(self, receipts, channel: str, ops, context, marker: str) -> List[Dict[str, Any]]:
        """Source-qualified receipts: relabelled, fake or mismatched rows are refused."""
        if receipts is None:
            receipts = []
        if not isinstance(receipts, list) or len(receipts) > 64:
            raise ValueError("receipts must be a list of at most 64 entries")
        allowed = CHANNEL_BASES[channel]
        def shape(url):
            parts = urlsplit(url)
            return (parts.scheme, norm_host(parts.hostname or ""), parts.port, parts.path or "/",
                    tuple(sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})))
        def matches(declared, actual):
            return (declared[:3] == actual[:3] and declared[4] == actual[4] and
                    (declared[3] == actual[3] or "{id}" in declared[3] and
                     declared[3] == template_path(actual[3])))
        op_keys = {(shape(o["url"]), o["method"], o["selector"], o["representation"],
                    o["version"]) for o in ops}
        out, seen = [], set()
        for item in receipts:
            if not isinstance(item, dict) or item.get("basis") not in allowed:
                raise ValueError(f"{channel} receipts must use basis {list(allowed)}")
            basis = item["basis"]
            if basis == "external-declared":
                _strict(item, "receipt", required=("basis", "label", "requests"))
                if not isinstance(item["label"], str) or not re.fullmatch(
                        re.escape(channel) + r":[A-Za-z0-9._:-]{1,100}", item["label"]):
                    raise ValueError(f"external receipts need a {channel}: label")
                key = (basis, item["label"])
                out.append({"basis": basis, "label": item["label"],
                            "requests": _int(item["requests"], "requests", 1, 1000),
                            "host": host_of(ops[0]["url"])})
            else:
                _strict(item, "receipt", required=("basis", "request_id"))
                rid = item["request_id"]
                if type(rid) is not int or rid < 1:
                    raise ValueError("receipt request_id must be a positive integer")
                row = self.db.execute(
                    "SELECT r.id,r.method,r.url,r.status,r.error,c.basis AS capture,c.context "
                    "FROM requests r LEFT JOIN response_capture c ON c.request_id=r.id WHERE r.id=?",
                    (rid,)).fetchone()
                if not row:
                    raise ValueError(f"receipt request {rid} does not exist")
                if (row["capture"] or "legacy-unattributed") != basis:
                    raise ValueError(f"request {rid} is {row['capture'] or 'legacy-unattributed'}, "
                                     f"not {basis}; a row cannot be relabelled")
                if not self.ctx.scope.is_in(row["url"]):
                    raise ValueError(f"request {rid} is outside the recorded scope")
                actual = shape(row["url"])
                if not any(matches(key, actual) and method in (row["method"], "UNKNOWN")
                           for key, method, selector, representation, version in op_keys):
                    raise ValueError(f"request {rid} is not one of this workflow's exact operations")
                labels = json.loads(row["context"] or "{}")
                if not isinstance(labels, dict):
                    raise ValueError(f"request {rid} has malformed capture labels")
                if channel in LIVE_CHANNELS and context is not None and any(
                        not labels.get(k) for k in ("account", "role", "tenant")):
                    raise ValueError(f"request {rid} lacks labelled live account/role/tenant evidence")
                if context is not None and labels.get("account") and labels["account"] != context["account"]:
                    raise ValueError(f"request {rid} belongs to another account context")
                if context is not None and any(labels.get(k) and labels[k] != context[col]
                       for k, col in (("role", "role"), ("tenant", "tenant"),
                                      ("session", "session"))):
                    raise ValueError(f"request {rid} belongs to another role/tenant/session")
                payload = self.ctx.store.request_payload(rid)
                body = b""
                if payload and payload["body_sha256"]:
                    body_path = self.ctx.store.bodies_dir / payload["body_sha256"]
                    body = body_path.read_bytes()[:5_000_001] if body_path.is_file() else b""
                if marker:
                    if marker.encode() not in body and marker not in row["url"]:
                        raise ValueError(f"request {rid} does not carry this event's marker")
                candidates = [(selector, representation, version) for key, method, selector,
                              representation, version in op_keys if matches(key, actual) and
                              method in (row["method"], "UNKNOWN")]
                if not any((not selector or selector.encode() in body) and
                           (not representation or payload is not None and
                            payload["content_type"] == representation.lower()) and
                           (not version or labels.get("version") == version)
                           for selector, representation, version in candidates):
                    raise ValueError(f"request {rid} lacks its declared selector/representation/version")
                key = (basis, rid)
                out.append({"basis": basis, "request_id": rid, "host": host_of(row["url"]),
                            "status": row["status"],
                            "delivered": "unknown" if row["error"] or row["status"] is None else "yes"})
            if key in seen:
                raise ValueError("duplicate receipt in one event")
            seen.add(key)
        return out

    def facts(self, raw, blobs) -> Dict[str, str]:
        if raw is None:
            return {}
        _strict(raw, "facts", optional=FACTS)
        out = {}
        for key, value in raw.items():
            if value not in ("yes", "no", "unknown"):
                raise ValueError("facts are yes, no or unknown")
            out[key] = value
        if "yes" in (out.get("committed"), out.get("effected"), out.get("compensated")) and \
                not {"oracle", "trace", "commit-trace"} & set(blobs):
            raise ValueError("committed/effected/compensated facts need an oracle or trace artifact")
        return out

    def impact(self, raw_tier, terminal, outcome, verdict, context, wf, inv, blobs, channel,
               view,
               object_ref, chain_finding, lineage, attacker_gain, window_evidence=False):
        """Terminal-impact ladder: tiers are earned from evidence and fall back, never inferred."""
        if raw_tier not in TIERS:
            raise ValueError("impact_tier T0..T4 is required on every event")
        supported, reasons = "T0", []
        resources = self.resources(wf["id"])
        target = resources.get(inv["resource"], {})
        if outcome == "observed" and verdict == "violated" and not window_evidence:
            if target.get("owned") and "oracle" in blobs:
                supported = "T1"
            else:
                reasons.append("T1 needs an owned resource and an authoritative oracle artifact")
        norm = None
        if terminal is not None:
            if not isinstance(terminal, dict) or terminal.get("kind") not in TERMINAL_KINDS:
                raise ValueError(f"terminal must be one object with kind in {TERMINAL_KINDS}")
            kind = terminal["kind"]
            if kind in ("owned-write", "entitlement"):
                _strict(terminal, "terminal", required=("kind", "object", "field", "before", "after"))
                obj = _text(terminal["object"], "terminal.object", 200, required=True)
                field = _ident(terminal["field"], "terminal.field")
                before, after = _scalar(terminal["before"], "before"), _scalar(terminal["after"], "after")
                owned = obj == object_ref and target.get("owned") and target.get("disposable")
                if not owned:
                    raise ValueError("an owned-write terminal must name this event's disposable owned "
                                     "object (--object-ref) on an owned, disposable resource")
                if before == after:
                    reasons.append("owned-write shows no change")
                elif not ({"owned-write", "readback"} <= set(blobs) and
                          obj.encode() in blobs["owned-write"] and field.encode() in blobs["owned-write"] and
                          str(after).encode() in blobs["readback"] and obj.encode() in blobs["readback"]):
                    reasons.append("T2 owned-write needs owned-write and independent readback artifacts "
                                   "binding the object, field and new value")
                elif outcome == "observed" and verdict == "violated" and not window_evidence:
                    supported = "T2"
                norm = {"kind": kind, "object": obj, "field": field, "before": before, "after": after}
            elif kind == "value-delta":
                _strict(terminal, "terminal", required=("kind", "currency", "exponent", "minor",
                                                        "cap_minor", "synthetic"))
                if terminal["synthetic"] is not True:
                    raise ValueError("live-money proofs are rejected; value-delta must use synthetic "
                                     "or sandbox units")
                exponent = _int(terminal["exponent"], "exponent", 0, 8)
                delta = money({"minor": terminal["minor"], "currency": terminal["currency"]},
                              terminal["currency"], exponent, "value-delta")
                cap = _int(terminal["cap_minor"], "cap_minor", 1, 1_000_000_000)
                if delta <= 0 or delta > cap:
                    raise ValueError("value-delta must be positive and within its declared cap")
                live_cap = self.logic_config["budget"]["value_cap_minor"]
                if channel in LIVE_CHANNELS and (live_cap == 0 or cap > live_cap):
                    raise ValueError("value-delta cap exceeds business_logic.budget.value_cap_minor")
                if "value-delta" in blobs and object_ref.encode() in blobs["value-delta"] and \
                          context["account"].encode() in blobs["value-delta"] and \
                          str(delta).encode() in blobs["value-delta"] and \
                          outcome == "observed" and verdict == "violated" and not window_evidence:
                    supported = "T2"
                else:
                    reasons.append("T2 value-delta needs a ledger artifact binding the owned object, "
                                   "account and exact minor-unit delta")
                norm = {"kind": kind, "currency": terminal["currency"], "exponent": exponent,
                        "minor": delta, "cap_minor": cap, "synthetic": True}
            else:
                _strict(terminal, "terminal", required=("kind", "account", "field", "records"))
                if terminal["records"] != 1 or type(terminal["records"]) is not int:
                    raise ValueError("bulk or multi-record reads are rejected; one owned field only")
                if terminal["account"] != context["account"] or context["account"] == "unknown":
                    raise ValueError("victim-read must be the operator's own labelled test account")
                field = _ident(terminal["field"], "terminal.field")
                if not ({"victim-read", "redacted", "ui-control"} <= set(blobs)):
                    reasons.append("T3 needs victim-read, redacted and ui-control artifacts")
                elif field.encode() not in blobs["victim-read"] or field.encode() in blobs["ui-control"] \
                        or b"[redacted]" not in blobs["redacted"].lower():
                    reasons.append("server read must carry the field, the UI control must lack it and "
                                   "the derivative must be redacted")
                elif outcome == "observed" and verdict == "violated" and not window_evidence:
                    supported = "T3"
                norm = {"kind": kind, "account": terminal["account"], "field": field, "records": 1}
            permit = "sensitive-read" if kind == "victim-read" else "state-changing"
            if channel in LIVE_CHANNELS and permit not in self.logic_config["permits"]:
                raise ValueError(f"{kind} terminal proofs stay owned-lab only: business_logic.permits "
                                 f"lacks {permit}")
        if raw_tier == "T4":
            if type(chain_finding) is not int:
                raise ValueError("T4 needs chain_finding: a target-class finding with shared lineage")
            row = self.db.execute("SELECT bug_class,stage,detail FROM findings WHERE id=?",
                                  (chain_finding,)).fetchone() if self._has_findings() else None
            detail = json.loads(row["detail"] or "{}") if row else {}
            shared = set(detail.get("lineage") or []) & set(lineage)
            source_class = "business-logic" if view == "logic" else "race-conditions"
            permitted = {target for source, target, _ in LINEAGE_HINTS if source == source_class}
            if not row or row["bug_class"] not in permitted or not shared or \
                    row["stage"] not in ("impact-proven", "reported", "accepted") or \
                    outcome != "observed" or verdict != "violated" or window_evidence:
                reasons.append("T4 needs the target class's own impact-proven finding with shared lineage")
            elif "lab-rehearsal" not in blobs:
                reasons.append("T4 needs a redacted owned-lab chain rehearsal artifact")
            elif not attacker_gain.strip():
                reasons.append("T4 needs the attacker-gain line")
            else:
                supported = "T4"
        order = {t: i for i, t in enumerate(TIERS)}
        tier = raw_tier if order[supported] >= order[raw_tier] else supported
        if raw_tier in ("T2", "T3") and tier == "T0" and outcome == "observed" and verdict == "violated":
            tier = "T1" if order[supported] >= 1 else "T0"
        return tier, norm, reasons

    def _has_findings(self) -> bool:
        return bool(self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='findings'"
                                    ).fetchone())

    def lineage(self, wf_key, inv, root_key) -> List[str]:
        keys = [f"invariant:{wf_key}/{inv['inv_key']}", f"resource:{wf_key}/{inv['resource']}"]
        if root_key:
            keys.append(f"root:{root_key}")
        return keys

    # ------------------------------------------------------------------ recording
    def record(self, view: str, env: Dict[str, Any], *, case: str, family_modes, ops, extra=None,
               window_evidence=False, concurrent=False, parallelism=None,
               scenario_id=None, prepaid=False) -> Dict[str, Any]:
        encoded = json.dumps(env, sort_keys=True, default=str).encode()
        if len(encoded) > MAX_DECLARATION or SECRET_RE.search(encoded):
            raise ValueError("event exceeds one mebibyte or appears to contain a raw secret")
        context = self.context(env.get("context"))
        wf, inv = self.current_invariant(context["wf_key"], env.get("invariant"))
        if not inv:
            raise ValueError("invariant is not declared in the context's latest workflow revision")
        outcome = env.get("outcome")
        channel = env.get("channel", "lab")
        if outcome not in OUTCOMES or channel not in CHANNELS:
            raise ValueError(f"outcome must be one of {OUTCOMES}; channel one of {CHANNELS}")
        basis = env.get("basis", CHANNEL_BASES[channel][-1] if channel in LIVE_CHANNELS else
                        CHANNEL_BASES[channel][0])
        if basis not in CHANNEL_BASES[channel]:
            raise ValueError(f"{channel} evidence uses basis {list(CHANNEL_BASES[channel])}")
        variant = _ident(env.get("variant", "default"), "variant")
        kind = env.get("kind", "test")
        marker, control_marker = env.get("marker", ""), env.get("control_marker", "")
        for label, value in (("marker", marker), ("control_marker", control_marker)):
            if value and not valid_marker(value):
                raise ValueError(f"{label} must be 16..96 characters of [A-Za-z0-9_-]")
        if control_marker and control_marker == marker:
            raise ValueError("control marker must differ from the attempt marker")
        note = _text(env.get("note", ""), "note")
        gain = _text(env.get("attacker_gain", ""), "attacker_gain", 200)
        root_key = env.get("root_key", "")
        if root_key:
            _ident(root_key, "root_key")
        object_ref = _text(env.get("object_ref", ""), "object_ref", 200)
        objects = _int(env.get("objects", 0), "objects", 0, 100)
        if channel in LIVE_CHANNELS and objects > 1:
            raise ValueError("live terminal cases use at most one disposable owned object")
        control = env.get("control", "")
        if control and control not in CONTROLS:
            raise ValueError(f"control must be one of {CONTROLS}")
        status = env.get("response_status")
        if status is not None:
            _int(status, "response_status", 100, 599)
        stop = env.get("stop_trigger", "")
        if stop and stop not in STOP_KINDS:
            raise ValueError(f"stop_trigger must be one of {STOP_KINDS}")
        if outcome in NOTE_OUTCOMES and not note.strip():
            raise ValueError(f"{outcome} needs a reason in note")
        if status == 429 and stop != "rate-limit":
            raise ValueError("429 is a stop: record outcome blocked with stop_trigger rate-limit")
        if status is not None and status >= 500 and stop != "server-error":
            raise ValueError("a 5xx is a stop: record outcome blocked with stop_trigger server-error")
        if stop and outcome not in ("blocked", "inconclusive"):
            raise ValueError("a stop trigger is recorded with outcome blocked or inconclusive")
        live = channel in LIVE_CHANNELS
        hosts = sorted({host_of(o["url"]) for o in ops})
        if channel == "review":
            if outcome not in REVIEW_OUTCOMES or objects or env.get("receipts"):
                raise ValueError("source review records only inconclusive/blocked/skipped/not-applicable "
                                 "and cannot claim observed acceptance, objects or receipts")
        if channel == "lab" and not all(lab_host(h) for h in hosts):
            raise ValueError("lab evidence is only for loopback or reserved test hosts")
        # Race members have distinct per-operation markers, verified by the race view.
        receipts = self.receipts(env.get("receipts"), channel, ops, context if view == "logic" else None,
                                  marker if view == "logic" else "")
        if any(r.get("status") == 429 for r in receipts) and stop != "rate-limit":
            raise ValueError("a stored 429 is a rate-limit stop, even without response_status")
        if any(r.get("status") is not None and r["status"] >= 500 for r in receipts) and \
                stop != "server-error":
            raise ValueError("a stored 5xx is a server-error stop, even without response_status")
        delivered_now = [r for r in receipts if r["basis"] in ("target-http", "external-declared")]
        if delivered_now and outcome not in ("blocked", "inconclusive") and \
                any(self.active_stop(h) for h in hosts):
            raise ValueError("a host in this workflow is stopped; review, then logic resume")
        if live and outcome in TRAFFIC_OUTCOMES:
            state, reason = self.live_gate(view, case, family_modes, context, wf, inv, ops,
                                           concurrent=concurrent, parallelism=parallelism, channel=channel,
                                           prepaid=prepaid)
            if state != "ready":
                raise ValueError(f"{case} is {state}: {reason}")
            if not receipts:
                raise ValueError("live attempts need source-qualified receipts")
            if prepaid and not any(r["basis"] == "external-declared" for r in receipts):
                raise ValueError("prepaid race attempts need their attested external receipt")
        data = self.artifacts(env.get("artifacts"))
        blobs = {role: blob for role, (_, blob) in data.items()}
        if env.get("terminal") is not None and (objects != 1 or not object_ref):
            raise ValueError("a terminal proof requires one named owned object and a cleanup obligation")
        facts = self.facts(env.get("facts"), blobs)
        if outcome == "observed" and any(r.get("delivered") == "unknown" for r in receipts):
            if not ({"commit-trace", "oracle"} <= set(blobs) and
                    facts.get("committed") == facts.get("effected") == "yes" and
                    marker and all(marker.encode() in blobs[role] for role in ("commit-trace", "oracle"))):
                raise ValueError("unknown delivery cannot become a commit from an error response; "
                                 "reconcile with a marker-bound owner commit trace and oracle")
        predicate = inv["predicate"]
        verdict, why = evaluate(predicate, wf, env.get("projections"), wf["policy_status"])
        control_verdict, _ = (evaluate(predicate, wf, env["control_projections"], wf["policy_status"])
                              if env.get("control_projections") is not None else ("", ""))
        baseline_verdict, _ = (evaluate(predicate, wf, env["baseline_projections"], wf["policy_status"])
                               if env.get("baseline_projections") is not None else ("", ""))
        if variant == "baseline" and outcome in ("observed", "negative-for-variant"):
            raise ValueError("a legitimate baseline is a positive control, not an observed effect or "
                             "negative security proof")
        if outcome == "observed":
            if channel == "review":
                raise ValueError("documentation-only evidence cannot claim an observed effect")
            if wf["policy_status"] not in TRUSTED_POLICY:
                raise ValueError("invariant policy unresolved; record inconclusive until the rule is documented")
            if inv["oracle"] == "client-value":
                raise ValueError("oracle-untrusted: a client-controlled value cannot prove an effect")
            if window_evidence:
                if verdict != "satisfied":
                    raise ValueError("window evidence means the invariant held under the declared schedule")
            elif verdict != "violated":
                raise ValueError(f"observed needs a violated invariant; projections say {verdict} ({why})")
            missing = {"before", "after", "oracle"} - set(blobs)
            if missing and not (window_evidence and "trace" in blobs):
                raise ValueError(f"observed evidence misses artifact roles {sorted(missing)}")
            if not window_evidence:
                if control_verdict != "satisfied" or "control" not in blobs or not control_marker:
                    raise ValueError("observed needs a control on the same invariant: control projections "
                                     "satisfied plus a control artifact with its own control marker")
                if marker.encode() in blobs["control"] or control_marker.encode() not in blobs["control"]:
                    raise ValueError("control artifact must carry its control marker and not the attempt marker")
                proof = [blobs[r] for r in ("after", "oracle", "trace") if r in blobs]
                if not valid_marker(marker) or not any(marker.encode() in b for b in proof):
                    raise ValueError("observed evidence must carry the fresh attempt marker")
                if len({_sha(blobs[r]) for r in ("before", "after", "control")}) != 3:
                    raise ValueError("before, after and control artifacts must be distinct")
        if outcome == "negative-for-variant":
            if verdict != "satisfied":
                raise ValueError(f"negative-for-variant needs satisfied projections; got {verdict} ({why})")
            if not control:
                raise ValueError("a refused outcome must name the control (fixed vocabulary; unknown allowed)")
            if not {"before", "after"} <= set(blobs) and channel != "review":
                raise ValueError("negative evidence needs before and after artifacts")
        if outcome == "pending" and "yes" not in (facts.get("accepted"), facts.get("queued")):
            raise ValueError("pending needs accepted=yes or queued=yes")
        if baseline_verdict and baseline_verdict != "satisfied":
            raise ValueError("baseline projections must satisfy the invariant (legitimate path)")
        parent = None
        if env.get("parent") is not None:
            parent = self.db.execute("SELECT * FROM workflow_events WHERE id=?",
                                     (env["parent"],)).fetchone()
            if not parent or parent["context_id"] != context["id"] or parent["inv_key"] != inv["inv_key"]:
                raise ValueError("parent must be an event on the same context and invariant")
        if kind == "replay":
            if parent is None or parent["outcome"] != "observed":
                raise ValueError("an independent replay names an observed parent event")
            if marker == parent["marker"]:
                raise ValueError("an independent replay needs a fresh marker")
            parent_blobs = self.blobs(parent["id"]) or {}
            if any(_sha(blobs[r]) == _sha(parent_blobs[r]) for r in ("after", "oracle")
                   if r in blobs and r in parent_blobs):
                raise ValueError("replay artifacts are identical to the parent; replay from fresh state")
            if self.event_state(dict(parent))[0] == "stale":
                raise ValueError("replay parent is stale or tampered")
        if outcome == "observed" and marker and self.db.execute(
                "SELECT 1 FROM workflow_events WHERE marker=? LIMIT 1", (marker,)).fetchone():
            raise ValueError("recycled marker: each observed event needs a fresh transport-attempt marker")
        lineage = self.lineage(context["wf_key"], inv, root_key)
        tier, terminal, tier_reasons = self.impact(
            env.get("impact_tier"), env.get("terminal"), outcome, verdict, context, wf, inv, blobs,
            channel, view, object_ref, env.get("chain_finding"), lineage, gain, window_evidence)
        next_play = env.get("next_play", "")
        if next_play and next_play not in PLAYS:
            raise ValueError(f"next_play must be one of {PLAYS}")
        if outcome == "observed" and tier in ("T0", "T1") and not next_play:
            raise ValueError("T0/T1 observations need a named next play or closed-lead")
        rubric = env.get("rubric")
        if rubric is not None:
            _strict(rubric, "rubric", optional=("preconditions", "blast_radius", "fix"))
            rubric = {k: _text(v, f"rubric.{k}", 500) for k, v in rubric.items()}
        if live and delivered_now:
            budget = self.logic_config["budget"]
            used = self.usage()
            new_native = {r["request_id"] for r in receipts if r["basis"] == "target-http"}
            seen = set()
            for r in self.db.execute("SELECT receipts FROM workflow_events"):
                for old in json.loads(r["receipts"]):
                    seen.add((old["basis"], old.get("request_id") or old.get("label")))
            if self.db.execute("SELECT 1 FROM sqlite_master WHERE name='race_attestations'").fetchone():
                for r in self.db.execute("SELECT label FROM race_attestations"):
                    seen.add(("external-declared", r["label"]))
            fresh = [r for r in receipts if (r["basis"], r.get("request_id") or r.get("label")) not in seen]
            add = sum(1 if r["basis"] == "target-http" else r["requests"] for r in fresh
                      if r["basis"] in ("target-http", "external-declared"))
            per_host = Counter()
            for r in fresh:
                if r["basis"] in ("target-http", "external-declared"):
                    per_host[r["host"]] += 1 if r["basis"] == "target-http" else r["requests"]
            if (used["native_measured"] + used["external_declared"] + add > budget["requests"] or
                    any(used["hosts"][h] + n > budget["per_host"] for h, n in per_host.items()) or
                    used["objects"] + objects > budget["objects"]):
                raise ValueError("shared business_logic budget exhausted; record blocked with "
                                 "stop_trigger budget and no new receipts")
            del new_native
        detail = {"facts": facts, "projections": env.get("projections"),
                  "control_projections": env.get("control_projections"),
                  "baseline_projections": env.get("baseline_projections"), "verdict_reason": why,
                  "terminal": terminal, "tier_reasons": tier_reasons, "rubric": rubric,
                   "chain_finding": env.get("chain_finding"), "lineage": lineage,
                   "next_play": next_play,
                  "window_evidence": window_evidence,
                  "non_rollback_effect": facts.get("effected") == "yes" and facts.get("compensated") == "yes",
                  "response_status": status, **(extra or {})}
        kept = self.keep(data)
        cur = self.db.execute(
            "INSERT INTO workflow_events(view,context_id,wf_key,inv_key,invariant_sha,case_id,variant,kind,"
            "scenario_id,outcome,channel,basis,marker,control_marker,control,verdict,control_verdict,"
            "detail,receipts,objects,object_ref,impact_claimed,impact_tier,attacker_gain,parent_id,"
            "root_key,policy_hash,facet_hash,note,created) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (view, context["id"], context["wf_key"], inv["inv_key"], inv["definition_sha"], case, variant,
             kind, scenario_id, outcome, channel, basis, marker, control_marker, control, verdict,
             control_verdict, json.dumps(detail, sort_keys=True, default=str), json.dumps(receipts),
             objects, object_ref, env.get("impact_tier"), tier, gain,
             parent["id"] if parent else None, root_key, self.policy_hash(), context["facets"], note,
             now()))
        event_id = cur.lastrowid
        for role, path, sha, size, source in kept:
            self.db.execute("INSERT INTO workflow_artifacts VALUES(?,?,?,?,?,?)",
                            (event_id, role, path, sha, size, source))
        retention = self.logic_config["retention_days"]
        host = hosts[0] if hosts else ""
        if objects:
            self.db.execute(
                "INSERT INTO workflow_obligations(event_id,host,kind,deadline,status,receipt,note,updated) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (event_id, host, "cleanup", self._deadline(days=retention), "open", "{}", inv["cleanup"], now()))
        if facts.get("effected") == "unknown" and outcome in ("pending", "inconclusive"):
            self.db.execute(
                "INSERT INTO workflow_obligations(event_id,host,kind,deadline,status,receipt,note,updated) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (event_id, host, "unknown-effect", self._deadline(seconds=inv["deadline_seconds"]),
                 "open", "{}", "reconcile against the authoritative oracle", now()))
        if stop:
            self.db.execute("INSERT INTO workflow_stops(host,stop_kind,event_id,created) VALUES(?,?,?,?)",
                            (host, stop, event_id, now()))
        self.db.commit()
        return {"event_id": event_id, "view": view, "case": case, "outcome": outcome, "channel": channel,
                "basis": basis, "verdict": verdict, "verdict_reason": why,
                "control_verdict": control_verdict or None, "impact_tier": tier,
                "impact_claimed": env.get("impact_tier"),
                "impact_downgraded": tier != env.get("impact_tier"), "tier_reasons": tier_reasons,
                "lineage": lineage, "lab_only": channel == "lab", "stopped_host": host if stop else None,
                "artifacts": len(kept), "receipts": len(receipts),
                "non_rollback_effect": detail["non_rollback_effect"], "retry": "none",
                "finding_promoted": False, "executed": False}

    @staticmethod
    def _deadline(days=0, seconds=0) -> str:
        return (datetime.now(timezone.utc) + timedelta(days=days, seconds=seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")

    # ------------------------------------------------------------------ state and verify
    def event_state(self, row: Dict[str, Any], depth: int = 0) -> Tuple[str, List[str]]:
        reasons = []
        blobs = self.blobs(row["id"])
        if blobs is None:
            reasons.append("artifact missing or tampered")
        if row["policy_hash"] != self.policy_hash():
            reasons.append("policy or program labels changed")
        try:
            context = self.context(row["context_id"])
            if context["facets"] != row["facet_hash"]:
                reasons.append("this context's captures changed")
        except ValueError:
            reasons.append("context missing")
        wf, inv = self.current_invariant(row["wf_key"], row["inv_key"])
        if not inv:
            reasons.append("invariant removed from the latest revision")
        elif inv["definition_sha"] != row["invariant_sha"]:
            reasons.append("invariant revised")
        if row["parent_id"] and depth < 20:
            parent = self.db.execute("SELECT * FROM workflow_events WHERE id=?", (row["parent_id"],)).fetchone()
            if not parent or self.event_state(dict(parent), depth + 1)[0] == "stale":
                reasons.append("parent stale or tampered")
        if not reasons and inv:
            detail = json.loads(row["detail"])
            try:
                again, _ = evaluate(inv["predicate"], wf, detail.get("projections"), wf["policy_status"])
                control, _ = evaluate(inv["predicate"], wf, detail.get("control_projections"),
                                      wf["policy_status"])
            except ValueError:
                again, control = "invalid", "invalid"
            if again != row["verdict"] or (row["control_verdict"] and control != row["control_verdict"]):
                reasons.append("verdict no longer reproduces from stored projections")
        return ("stale", reasons) if reasons else (row["outcome"], [])

    def verify(self, view=None) -> Dict[str, Any]:
        integrity, evidence, stale = [], [], []
        query = "SELECT * FROM workflow_events" + (" WHERE view=?" if view else "") + " ORDER BY id"
        rows = self.db.execute(query, (view,) if view else ()).fetchall()
        for r in rows:
            row = dict(r)
            if self.blobs(row["id"]) is None:
                integrity.append({"event": row["id"], "reason": "artifact missing or tampered"})
                continue
            state, reasons = self.event_state(row)
            if "verdict no longer reproduces from stored projections" in reasons:
                evidence.append({"event": row["id"], "reason": "stored projections no longer evaluate "
                                 "to the recorded verdict"})
            elif state == "stale":
                stale.append({"event": row["id"], "reasons": reasons})
        for r in self.db.execute("SELECT id,receipt FROM workflow_obligations ORDER BY id"):
            ref = json.loads(r["receipt"] or "{}")
            if ref.get("path"):
                try:
                    data = local_bytes(self.ctx.campaign.root, ref["path"])
                    if _sha(data) != ref["sha256"]:
                        raise ValueError
                except (ValueError, OSError):
                    integrity.append({"obligation": r["id"], "reason": "cleanup receipt missing or tampered"})
        return {"verified": not integrity and not evidence, "artifact_integrity": not integrity,
                "invalid": (integrity + evidence)[:100], "stale": stale[:100],
                "events_checked": len(rows),
                "basis": "hashes detect changed bytes, not forged source evidence; stale events keep "
                         "their history but lose current readiness", "executed": False}

    # ------------------------------------------------------------------ obligations and stops
    def cleanup(self, event_id, outcome, artifact="", note="") -> Dict[str, Any]:
        if type(event_id) is not int:
            raise ValueError("event must be an integer ID")
        event = self.db.execute("SELECT * FROM workflow_events WHERE id=?", (event_id,)).fetchone()
        if not event:
            raise ValueError("unknown event")
        if outcome not in CLEANUP_OUTCOMES:
            raise ValueError(f"outcome must be one of {CLEANUP_OUTCOMES}")
        note = _text(note, "note")
        open_rows = [dict(r) for r in self.db.execute(
            "SELECT * FROM workflow_obligations WHERE event_id=? AND status NOT IN ('resolved')", (event_id,))]
        if not open_rows:
            raise ValueError("this event has no open cleanup or unknown-effect obligation")
        receipt = {}
        if artifact:
            data = self.artifacts([f"receipt={artifact}"])
            path, sha, size = self.keep(data)[0][1:4]
            receipt = {"path": path, "sha256": sha, "bytes": size}
            blob = data["receipt"][1]
        else:
            blob = None
        if outcome in CLEANUP_DONE:
            tokens = [t for t in (event["marker"], event["object_ref"]) if t]
            if blob is None or not any(t.encode() in blob for t in tokens):
                raise ValueError(f"{outcome} needs a receipt naming the event marker or object reference")
            kinds = ("unknown-effect",) if outcome == "reconciled" else ("cleanup",)
            if outcome == "reconciled" and not any(r["kind"] == "unknown-effect" for r in open_rows):
                raise ValueError("reconciled resolves an unknown-effect obligation; none is open")
            status = "resolved"
        else:
            if not note.strip():
                raise ValueError("explain the unresolved cleanup in note")
            kinds, status = ("cleanup", "unknown-effect"), outcome
        targets = [r for r in open_rows if r["kind"] in kinds]
        for r in targets:
            self.db.execute("UPDATE workflow_obligations SET status=?,receipt=?,note=?,updated=? WHERE id=?",
                            (status, json.dumps(receipt), note or r["note"], now(), r["id"]))
        stopped = None
        if status in ("failed", "unverified"):
            stopped = targets[0]["host"] if targets else open_rows[0]["host"]
            self.db.execute("INSERT INTO workflow_stops(host,stop_kind,event_id,created) VALUES(?,?,?,?)",
                            (stopped, "cleanup-unresolved", event_id, now()))
        self.db.commit()
        return {"event_id": event_id, "outcome": outcome, "resolved": status == "resolved",
                "obligations": len(targets), "stopped_host": stopped,
                "basis": "the ledger records receipts; it deletes nothing and sends nothing",
                "executed": False}

    def obligations(self) -> List[Dict[str, Any]]:
        stamp = now()
        out = []
        for r in self.db.execute("SELECT * FROM workflow_obligations WHERE status<>'resolved' ORDER BY id"):
            out.append({"id": r["id"], "event": r["event_id"], "host": r["host"], "kind": r["kind"],
                        "status": r["status"], "deadline": r["deadline"],
                        "overdue": bool(r["deadline"]) and stamp > r["deadline"]})
        return out

    def resume(self, host, note) -> Dict[str, Any]:
        host = norm_host(host or "")
        note = _text(note, "note")
        if not host or not note.strip():
            raise ValueError("resume needs the stopped host and why it is safe to continue")
        active = [dict(r) for r in self.db.execute(
            "SELECT * FROM workflow_stops WHERE host=? AND cleared='' ORDER BY id", (host,))]
        if not active:
            raise ValueError(f"host {host} is not stopped")
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='race_attestations'").fetchone():
            for att in self.db.execute("SELECT id,members FROM race_attestations WHERE host=?", (host,)):
                if None in json.loads(att["members"]) and not self.db.execute(
                        "SELECT 1 FROM race_runs WHERE attestation_id=?", (att["id"],)).fetchone():
                    raise ValueError("missing member response is charged but has no reconciled run; "
                                     "record its inconclusive unknown-effect event first")
        blocking = [o for o in self.obligations() if o["host"] == host and
                    (o["status"] in ("failed", "unverified") or o["kind"] == "unknown-effect")]
        if blocking:
            raise ValueError("failed cleanup or an unreconciled unknown effect blocks resume; record "
                             "a receipt with cleanup first")
        self.db.execute("UPDATE workflow_stops SET cleared=?,clear_note=? WHERE host=? AND cleared=''",
                        (now(), note, host))
        self.db.commit()
        return {"host": host, "cleared": [r["stop_kind"] for r in active],
                "basis": "ledger readiness only; current send/Burp traffic is not intercepted",
                "executed": False}

    def stops(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT host,stop_kind,event_id,created FROM workflow_stops WHERE cleared='' ORDER BY id")]

    # ------------------------------------------------------------------ chains
    def chain_next(self) -> List[Dict[str, Any]]:
        """Lineage-gated hints: a shared invariant/resource/root key, never class coincidence."""
        sources = defaultdict(list)
        for r in self.db.execute("SELECT * FROM workflow_events WHERE outcome='observed' ORDER BY id"):
            row = dict(r)
            if self.event_state(row)[0] == "stale":
                continue
            detail = json.loads(row["detail"])
            if detail.get("window_evidence") or row["verdict"] != "violated":
                continue
            cls = "business-logic" if row["view"] == "logic" else "race-conditions"
            wf, inv = self.current_invariant(row["wf_key"], row["inv_key"])
            if not inv:
                continue
            kind = self.resources(wf["id"]).get(inv["resource"], {}).get("kind", "")
            sources[cls].append({"view": row["view"], "event": row["id"], "lineage": detail["lineage"],
                                 "crown_jewel": wf["crown_jewel"], "resource_kind": kind,
                                 "tier": row["impact_tier"], "gain": row["attacker_gain"]})
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authz_events'").fetchone():
            for r in self.db.execute("SELECT id,root_key FROM authz_events WHERE case_id='ma-privileged-field' "
                                     "AND state='observed' AND root_key<>''"):
                sources["mass-assignment"].append({"view": "authz", "event": r["id"],
                                                   "lineage": [f"root:{r['root_key']}"],
                                                   "crown_jewel": "entitlement", "resource_kind": "",
                                                   "tier": "", "gain": ""})
        findings = []
        if self._has_findings():
            for r in self.db.execute("SELECT id,bug_class,stage,detail FROM findings"):
                if r["stage"] in ("killed", "duplicate", "informative", "n-a"):
                    continue
                lineage = set((json.loads(r["detail"] or "{}").get("lineage") or []))
                if lineage:
                    findings.append({"id": r["id"], "class": r["bug_class"], "stage": r["stage"],
                                     "lineage": lineage})
        logic_keys = {k for s in sources["business-logic"] for k in s["lineage"]}
        hints = []
        for src_cls, dst_cls, meaning in LINEAGE_HINTS:
            for src in sources[src_cls]:
                applies = {("business-logic", "access-control"): src["crown_jewel"] in ("entitlement", "admin"),
                           ("business-logic", "ato"): src["crown_jewel"] == "identity",
                           ("race-conditions", "business-logic"): True,
                           ("race-conditions", "ato"): src["resource_kind"] in AUTH_ARTIFACT_KINDS,
                           ("mass-assignment", "business-logic"): bool(set(src["lineage"]) & logic_keys) or
                           any(f["class"] == "business-logic" and set(src["lineage"]) & f["lineage"]
                               for f in findings)}[(src_cls, dst_cls)]
                if not applies:
                    continue
                matches = [f for f in findings if f["class"] == dst_cls and set(src["lineage"]) & f["lineage"]]
                if matches:
                    best = max(matches, key=lambda f: f["stage"] in ("impact-proven", "reported", "accepted"))
                    state = "t4-eligible" if best["stage"] in ("impact-proven", "reported", "accepted") \
                        else "linked"
                    target = best["id"]
                else:
                    state, target = "next", None
                hints.append({"hint": f"{src_cls}->{dst_cls}", "meaning": meaning, "state": state,
                              "play": ("P1-entitlement-action" if dst_cls == "access-control" else
                                       "P2-artifact-account" if dst_cls == "ato" else
                                       "P3-value-effect"),
                              "source": {"view": src["view"], "event": src["event"]},
                              "lineage": src["lineage"], "target_finding": target,
                              "crown_jewel": src["crown_jewel"], "attacker_gain": src["gain"]})
        order = {"t4-eligible": 0, "linked": 1, "next": 2}
        hints.sort(key=lambda h: (order[h["state"]], CROWN_RANK.get(h["crown_jewel"], 9), h["hint"]))
        return hints[:50]

    def coarse_conflicts(self, open_assets) -> List[List[Any]]:
        out = []
        for row in self.ctx.store.coverage():
            if row["bug_class"] in ("business-logic", "race-conditions") and \
                    row["status"] in ("tested", "confirmed", "refuted", "n-a") and \
                    row["asset_id"] in open_assets:
                out.append([row["asset_id"], row["bug_class"], row["status"]])
        return out[:100]

    def operation_assets(self, wf) -> set:
        ids = set()
        for op in self.operations(wf["id"]):
            try:
                asset = self.ctx.store.find_asset("endpoint", endpoint_key(op["url"]))
            except (ValueError, OutOfScope):
                asset = None
            if asset:
                ids.add(asset["id"])
        return ids
