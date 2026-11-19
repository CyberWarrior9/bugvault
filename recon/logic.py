"""Offline business-logic discovery and exact-invariant evidence view.

Candidates and differential observations are leads, never policy violations. No
network client, target executor or finding promotion is reachable from this module.
"""
from __future__ import annotations

import json
from collections import Counter

from .invariants import Model, _ident, _strict, _text
from .store import now

CASES = tuple(f"BL-{i:02d}" for i in range(1, 19))
LAB_ONLY = {"BL-06", "BL-07", "BL-09", "BL-11", "BL-12", "BL-16", "BL-17"}
SWEEP = {
    "quantity": ("zero", "negative", "fractional", "above-declared-bound", "unit-mismatch"),
    "price": ("amount-change", "currency-change", "rounding-boundary"),
    "coupon": ("stacked", "repeated", "out-of-scope", "expired"),
    "sequence": ("skip", "reorder", "repeat", "pending-reentry"),
    "idempotency": ("same-key-same-body", "same-key-changed-body", "new-key-same-body"),
    "entitlement": ("field-change", "terminal-replay"),
}
DISCOVERY = """
CREATE TABLE IF NOT EXISTS hunt_observations(
 id INTEGER PRIMARY KEY, wf_key TEXT NOT NULL, context_id INTEGER NOT NULL,
 operation TEXT NOT NULL, dimension TEXT NOT NULL, variant TEXT NOT NULL,
 policy_status TEXT NOT NULL, tier TEXT NOT NULL, suspected_rule TEXT NOT NULL,
 baseline_path TEXT NOT NULL, baseline_sha TEXT NOT NULL,
 variant_path TEXT NOT NULL, variant_sha TEXT NOT NULL,
 oracle_path TEXT NOT NULL, oracle_sha TEXT NOT NULL,
 promotion_event INTEGER, close_reason TEXT NOT NULL DEFAULT '', created TEXT NOT NULL);
"""


class LogicLedger:
    def __init__(self, ctx):
        self.model = Model(ctx)
        self.db = self.model.db
        self.db.executescript(DISCOVERY)
        self.db.commit()

    def sync(self):
        stats = self.model.sync_contexts()
        # No inferred sibling route, source declaration or JS reference is acceptance.
        candidates = [dict(id=r["asset_id"], endpoint=r["asset_value"], reason=r["reason"])
                      for r in self.model.ctx.store.coverage() if r["bug_class"] == "business-logic"]
        return {"contexts": stats, "candidate_count": len(candidates),
                "candidates": candidates[:50], "truncated": len(candidates) > 50,
                "basis": "captured/seeded operations only; declaration still requires a rule",
                "executed": False, "finding_promoted": False}

    def declare(self, data):
        return self.model.declare(data)

    def probe(self, workflow, limit=50):
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("probe limit must be 1..50")
        wf = self.model.workflow(_ident(workflow, "workflow"))
        if not wf:
            raise ValueError("declare a workflow before planning its differential sweep")
        cards = []
        for op in self.model.operations(wf["id"]):
            if not op["in_scope"]:
                continue
            if op["method"] not in ("POST", "PUT", "PATCH", "DELETE", "UNKNOWN"):
                continue
            names = op["fields"]
            dimensions = [d for d in SWEEP if any(d in f.lower() for f in names)]
            if op["transition"]:
                dimensions.append("sequence")
            if any("key" in f.lower() for f in names):
                dimensions.append("idempotency")
            for dimension in dict.fromkeys(dimensions):
                for variant in SWEEP[dimension]:
                    cards.append({"operation": op["op_key"], "dimension": dimension,
                                  "variant_class": variant, "baseline": "fresh owned valid path",
                                  "observation": "compare independent owned state; a response is not a commit",
                                  "stop": "429, challenge, 5xx, unexpected effect or cap"})
        return {"workflow": workflow, "policy_status": wf["policy_status"],
                "cards": cards[:limit], "total": len(cards), "truncated": len(cards) > limit,
                "executed": False, "finding_promoted": False,
                "basis": "value-free cards, not generated payloads or target requests"}

    def observe(self, env):
        """Record a lightweight differential with copied, hash-bound redacted artifacts."""
        _strict(env, "hunt observation", required=("context", "operation", "dimension", "variant",
                                                   "suspected_rule", "baseline", "attempt"),
                optional=("oracle", "tier"))
        ctx = self.model.context(env["context"])
        wf = self.model.workflow(ctx["wf_key"])
        if not wf:
            raise ValueError("unknown workflow")
        if (ctx["basis"] != "owned-loopback-declared" and
                ctx["account"] not in self.model.logic_config["owned_accounts"]):
            raise ValueError("hunt observations require a labelled operator-owned test account")
        op = next((o for o in self.model.operations(wf["id"]) if o["op_key"] == env["operation"]), None)
        if not op or not op["in_scope"]:
            raise ValueError("observation must bind an exact in-scope declared operation")
        dimension = env["dimension"]
        if dimension not in SWEEP or env["variant"] not in SWEEP[dimension]:
            raise ValueError("unsupported differential dimension/variant class")
        tier = env.get("tier", "T0")
        if tier not in ("T0", "T1"):
            raise ValueError("hunt observations are T0/T1 only")
        rule = _text(env["suspected_rule"], "suspected_rule", 500, required=True)
        names = [f"baseline={env['baseline']}", f"after={env['attempt']}"]
        if env.get("oracle"):
            names.append(f"oracle={env['oracle']}")
        data = self.model.artifacts(names)
        if data["baseline"][1] == data["after"][1]:
            raise ValueError("baseline and attempt must differ; no differential observed")
        if tier == "T1" and "oracle" not in data:
            raise ValueError("T1 needs an independent owned-state oracle")
        if tier == "T1" and not any(r["owned"] for r in self.model.resources(wf["id"]).values()):
            raise ValueError("T1 needs an owned resource")
        kept = {r: (path, sha) for r, path, sha, _, _ in self.model.keep(data)}
        cur = self.db.execute(
            "INSERT INTO hunt_observations(wf_key,context_id,operation,dimension,variant,policy_status,"
            "tier,suspected_rule,baseline_path,baseline_sha,variant_path,variant_sha,oracle_path,"
            "oracle_sha,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (wf["wf_key"], ctx["id"], op["op_key"], dimension, env["variant"],
             wf["policy_status"], tier, rule, *kept["baseline"], *kept["after"],
             *(kept.get("oracle") or ("", "")), now()))
        self.db.commit()
        return {"observation_id": cur.lastrowid, "tier": tier, "policy_status": wf["policy_status"],
                "verdict": "unadjudicated lead", "executed": False, "finding_promoted": False}

    def close(self, observation_id, reason, event_id=None):
        reason = _text(reason, "reason", 500, required=True)
        row = self.db.execute("SELECT * FROM hunt_observations WHERE id=?", (observation_id,)).fetchone()
        if not row or row["close_reason"]:
            raise ValueError("observation missing or already closed")
        if event_id is not None:
            event = self.db.execute("SELECT * FROM workflow_events WHERE id=?", (event_id,)).fetchone()
            if not event or event["view"] != "logic" or event["context_id"] != row["context_id"]:
                raise ValueError("promotion must cite a logic event on the same context")
            if event["outcome"] != "observed" or self.model.event_state(dict(event))[0] == "stale":
                raise ValueError("promotion needs a fresh observed case with full evidence")
            wf = self.model.workflow(row["wf_key"])
            if not wf or wf["policy_status"] not in ("declared", "documented", "owner-confirmed"):
                raise ValueError("promotion needs a declared rule")
        self.db.execute("UPDATE hunt_observations SET close_reason=?,promotion_event=? WHERE id=?",
                        (reason, event_id, observation_id))
        self.db.commit()
        return {"observation_id": observation_id, "promoted": event_id is not None,
                "finding_promoted": False, "executed": False}

    def plan(self, workflow=None, limit=25):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")
        rows = []
        for wf in self.model.workflows():
            if workflow and wf["wf_key"] != workflow:
                continue
            ops = self.model.operations(wf["id"])
            for context in self.model.contexts(wf["wf_key"]):
                for inv in self.model.invariants(wf["id"]):
                    modes = ("R", "L") if inv["family"] in LAB_ONLY else ("R", "L", "C-S")
                    state, reason = self.model.live_gate("logic", inv["family"], modes,
                                                          context, wf, inv, ops)
                    rows.append({"workflow": wf["wf_key"], "context": context["id"],
                                 "invariant": inv["inv_key"], "case": inv["family"],
                                 "policy_status": wf["policy_status"], "readiness": state,
                                 "reason": reason})
        return {"rows": rows[:limit], "total": len(rows), "truncated": len(rows) > limit,
                "executed": False, "finding_promoted": False}

    def record(self, env):
        _strict(env, "logic event", required=("context", "invariant", "case", "outcome", "impact_tier"),
                optional=("channel", "basis", "variant", "kind", "marker", "control_marker",
                          "control", "note", "attacker_gain", "root_key", "object_ref", "objects",
                          "response_status", "stop_trigger", "receipts", "artifacts", "facts",
                          "projections", "control_projections", "baseline_projections", "parent",
                          "terminal", "chain_finding", "rubric", "next_play"))
        case = env["case"]
        if case not in CASES:
            raise ValueError("unknown BL family")
        context = self.model.context(env["context"])
        wf, inv = self.model.current_invariant(context["wf_key"], env["invariant"])
        if not inv or inv["family"] != case:
            raise ValueError("case must match the declared invariant family")
        ops = self.model.operations(wf["id"])
        # Lab and review are allowed on nonfinancial cases; live readiness is fail-closed.
        family_modes = ("R", "L") if case in LAB_ONLY else ("R", "L", "C-S")
        result = self.model.record("logic", env, case=case, family_modes=family_modes, ops=ops)
        if env["outcome"] == "negative-for-variant" and env.get("control") not in ("", "unknown", None):
            from .race import RaceLedger
            result["race_candidate_scenario"] = RaceLedger(self.model.ctx).escalate(result["event_id"])
        return result

    def verify(self):
        from .callbacks import local_bytes
        from .invariants import _sha
        result = self.model.verify("logic")
        invalid = list(result["invalid"])
        for row in self.db.execute("SELECT * FROM hunt_observations ORDER BY id"):
            for prefix in ("baseline", "variant", "oracle"):
                path, sha = row[f"{prefix}_path"], row[f"{prefix}_sha"]
                if not path:
                    continue
                try:
                    if _sha(local_bytes(self.model.ctx.campaign.root, path)) != sha:
                        raise ValueError("hash differs")
                except (ValueError, OSError):
                    invalid.append({"observation": row["id"], "role": prefix, "reason": "missing/tampered"})
        result.update({"verified": not invalid and result["verified"], "invalid": invalid[:100],
                       "observations_checked": self.db.execute("SELECT count(*) FROM hunt_observations").fetchone()[0],
                       "finding_promoted": False})
        return result

    def status(self, limit=25):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")
        verify = self.verify()
        observations = [dict(r) for r in self.db.execute(
            "SELECT id,wf_key,context_id,dimension,variant,policy_status,tier,promotion_event,close_reason "
            "FROM hunt_observations ORDER BY id DESC")]
        events = [dict(r) for r in self.db.execute(
            "SELECT id,context_id,case_id,outcome,impact_tier,channel,parent_id FROM workflow_events "
            "WHERE view='logic' ORDER BY id DESC")]
        replays = {e["parent_id"] for e in events if e["parent_id"] and e["outcome"] == "observed"}
        for event in events:
            row = self.db.execute("SELECT * FROM workflow_events WHERE id=?", (event["id"],)).fetchone()
            state = self.model.event_state(dict(row))[0]
            detail = json.loads(row["detail"])
            rubric = detail.get("rubric") or {}
            ready = (event["id"] in replays and event["impact_tier"] in ("T2", "T3", "T4") and
                     event["outcome"] == "observed" and bool(row["attacker_gain"].strip()) and
                     all(rubric.get(k) for k in ("preconditions", "blast_radius", "fix")) and
                     not any(o["event"] == event["id"] for o in self.model.obligations()))
            event["readiness"] = ("stale" if state == "stale" else "lab-only-review" if event["channel"] == "lab"
                                  else "validator-ready" if ready else "open")
        return {"observations": observations[:limit], "observation_total": len(observations),
                "events": events[:limit], "event_total": len(events),
                "totals": dict(Counter(e["outcome"] for e in events)),
                "verify": verify, "obligations": self.model.obligations()[:limit],
                "stops": self.model.stops()[:limit], "chain_next": self.model.chain_next()[:limit],
                "executed": False, "finding_promoted": False}
