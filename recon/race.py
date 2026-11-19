"""Offline race scenario, signal, measurement and operator-attestation view.

This module never opens a connection or releases a gate. External labels are
operator declarations, not synchronized-execution or application-commit proof.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import urlsplit

from .invariants import (CONCURRENCY_RELEVANT, CONTROLS, LIVE_CHANNELS, Model,
                         _ident, _int, _sha, _strict, _text, host_of)
from .callbacks import local_bytes, valid_marker
from .store import now

CASES = tuple(f"RC-{i:02d}" for i in range(1, 22))
SCHEDULES = ("serial-ab", "serial-ba", "concurrent", "fixed", "replay")
LAB_ONLY = {"RC-04", "RC-07", "RC-09", "RC-10", "RC-11", "RC-15", "RC-16", "RC-18"}
WINDOW_CONTROLS = ("atomicity", "serialization")
SIGNALS = re.compile(r"(?<![a-z])(?:redeem|transfer|withdraw|invite|upvote|coupon|"
                     r"quota|credit|refund|claim|approve|reserve|consume|reset|verify|"
                     r"entitle|finalize)(?![a-z])", re.I)
JS_TELLS = (("button-disable", re.compile(rb"\.disabled\s*=\s*true|setDisabled\(true\)", re.I)),
            ("optimistic-update", re.compile(rb"optimistic|setState\([^)]*\)\s*;\s*fetch\(", re.I)),
            ("sequential-await", re.compile(rb"await\s+[^;]{1,150};\s*await\s+", re.I)))
STACK_TELLS = (("non-atomic-counter", re.compile(r"read.modify.write|non.atomic|counter", re.I)),
               ("queue-without-key", re.compile(r"queue.*(?:no|without).{0,20}idemp", re.I)),
               ("lock-missing", re.compile(r"(?:no|missing|without).{0,20}lock", re.I)))

SCHEMA = """
CREATE TABLE IF NOT EXISTS race_members(
 scenario_id INTEGER NOT NULL REFERENCES race_scenarios(id), position INTEGER NOT NULL,
 op_key TEXT NOT NULL, context_id INTEGER NOT NULL REFERENCES workflow_contexts(id),
 intent TEXT NOT NULL, PRIMARY KEY(scenario_id, position));
CREATE TABLE IF NOT EXISTS race_attestations(
 id INTEGER PRIMARY KEY, scenario_id INTEGER NOT NULL REFERENCES race_scenarios(id),
 label TEXT NOT NULL UNIQUE, host TEXT NOT NULL, tool TEXT NOT NULL, engine TEXT NOT NULL,
 version TEXT NOT NULL, protocol TEXT NOT NULL, gate TEXT NOT NULL, operator TEXT NOT NULL,
 sent INTEGER NOT NULL, retries INTEGER NOT NULL, requests INTEGER NOT NULL,
 connections INTEGER NOT NULL, members TEXT NOT NULL,
 path TEXT NOT NULL, sha256 TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS race_runs(
 id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL UNIQUE REFERENCES workflow_events(id),
 scenario_id INTEGER NOT NULL REFERENCES race_scenarios(id), schedule TEXT NOT NULL,
 parallelism INTEGER, attempts INTEGER, successes INTEGER, window_evidence INTEGER NOT NULL,
 timing_quality TEXT NOT NULL, sync_declared INTEGER NOT NULL, sync_evidenced INTEGER NOT NULL,
 attestation_id INTEGER REFERENCES race_attestations(id), members TEXT NOT NULL, created TEXT NOT NULL);
"""


class RaceLedger:
    def __init__(self, ctx):
        self.model = Model(ctx)
        self.db = self.model.db
        self.db.executescript(SCHEMA)
        self.db.commit()

    def _scenario(self, scenario_id):
        if type(scenario_id) is not int or scenario_id < 1:
            raise ValueError("scenario must be a positive integer")
        row = self.db.execute("SELECT * FROM race_scenarios WHERE id=?", (scenario_id,)).fetchone()
        if not row:
            raise ValueError("unknown race scenario")
        return dict(row)

    def _members(self, scenario_id):
        return [dict(r) for r in self.db.execute("SELECT * FROM race_members WHERE scenario_id=? "
                                               "ORDER BY position", (scenario_id,))]

    def _ops(self, wf, members):
        all_ops = {o["op_key"]: o for o in self.model.operations(wf["id"])}
        return [all_ops[m["op_key"]] for m in members]

    def declare(self, env):
        _strict(env, "race scenario", required=("schema", "workflow", "invariant", "context", "family",
                                               "resource", "members", "order_matters"),
                optional=("source_event", "surviving_control"))
        if env["schema"] != 1 or type(env["schema"]) is not int:
            raise ValueError("unsupported race scenario schema")
        wf, inv = self.model.current_invariant(_ident(env["workflow"], "workflow"),
                                               _ident(env["invariant"], "invariant"))
        if not inv or inv["resource"] != env["resource"]:
            raise ValueError("scenario needs a current invariant and its exact resource")
        family = env["family"]
        if family not in CASES:
            raise ValueError("unknown RC family")
        if type(env["order_matters"]) is not bool:
            raise ValueError("order_matters must be boolean")
        ctx = self.model.context(env["context"])
        if ctx["wf_key"] != wf["wf_key"]:
            raise ValueError("scenario context belongs to another workflow")
        resource = self.model.resources(wf["id"]).get(env["resource"])
        if not resource or not resource["owned"] or not resource["shared"]:
            raise ValueError("race resource needs declared owned/shared identity (not path similarity)")
        members = env["members"]
        if not isinstance(members, list) or not 2 <= len(members) <= 8:
            raise ValueError("scenario needs 2..8 exact operation members")
        all_ops = {o["op_key"]: o for o in self.model.operations(wf["id"])}
        normalized = []
        for m in members:
            _strict(m, "member", required=("operation", "context", "intent"))
            op_key = _ident(m["operation"], "operation")
            other = self.model.context(m["context"])
            op = all_ops.get(op_key)
            if not op or not op["in_scope"] or other["wf_key"] != wf["wf_key"]:
                raise ValueError("every member must name an in-scope exact operation and workflow context")
            if env["resource"] not in set().union(*(set(op["touches"][k]) for k in
                                                     ("writes", "consumes", "publishes", "enqueues"))):
                raise ValueError("member must explicitly write/consume/publish/enqueue the same resource")
            normalized.append((op_key, other["id"], _ident(m["intent"], "intent")))
        if len(normalized) > 2 and len({m[0] for m in normalized}) != len(normalized):
            raise ValueError("fan-out of 3..8 requires distinct exact writers")
        if len({(m[0], m[1], m[2]) for m in normalized}) != len(normalized):
            raise ValueError("members must have distinct operation/context/intent identity")
        if family == "RC-21":
            if resource["kind"] not in ("otp", "reset-token", "invite", "magic-link", "session",
                                         "verification-code"):
                raise ValueError("RC-21 requires a declared one-time owned auth artifact")
            if len({self.model.context(m[1])["account"] for m in normalized}) != 2:
                raise ValueError("RC-21 requires two separately labelled owned A/V contexts")
        control = env.get("surviving_control", "")
        if control and control not in CONTROLS:
            raise ValueError("unknown surviving control")
        source = env.get("source_event")
        if source is not None:
            row = self.db.execute("SELECT * FROM workflow_events WHERE id=?", (source,)).fetchone()
            if not row or row["view"] != "logic" or row["context_id"] != ctx["id"] or \
                    row["inv_key"] != inv["inv_key"] or row["outcome"] != "negative-for-variant" or \
                    row["control"] != control or not control or control == "unknown":
                raise ValueError("sequence escalation needs a matching survived logic event and named control")
        # Existing two-column unique key is supplemented by a member-list comparison below.
        old = self.db.execute("SELECT * FROM race_scenarios WHERE wf_key=? AND inv_key=? AND "
                              "context_id=? AND family=? AND member_a=? AND member_b=?",
                              (wf["wf_key"], inv["inv_key"], ctx["id"], family,
                               normalized[0][0], normalized[1][0])).fetchone()
        if old:
            stored = [(m["op_key"], m["context_id"], m["intent"]) for m in self._members(old["id"])]
            if stored != normalized or old["resource"] != env["resource"]:
                raise ValueError("a scenario with those members already exists; do not overwrite its lineage")
            return {"scenario_id": old["id"], "unchanged": True, "executed": False,
                    "finding_promoted": False}
        cur = self.db.execute("INSERT INTO race_scenarios(wf_key,inv_key,context_id,family,member_a,member_b,"
                              "resource,order_matters,source_event_id,surviving_control,created) "
                              "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                              (wf["wf_key"], inv["inv_key"], ctx["id"], family,
                               normalized[0][0], normalized[1][0], env["resource"],
                               int(env["order_matters"]), source, control, now()))
        for index, (key, context, intent) in enumerate(normalized):
            self.db.execute("INSERT INTO race_members VALUES(?,?,?,?,?)",
                            (cur.lastrowid, index, key, context, intent))
        self.db.commit()
        return {"scenario_id": cur.lastrowid, "members": len(normalized), "unchanged": False,
                "executed": False, "finding_promoted": False}

    def sync(self):
        contexts = self.model.sync_contexts()
        escalated = 0
        for row in self.db.execute("SELECT * FROM workflow_events WHERE view='logic' AND "
                                   "outcome='negative-for-variant' AND control NOT IN ('','unknown')"):
            if self.escalate(row["id"]):
                escalated += 1
        profiles = self._signals()
        return {"contexts": contexts, "escalated": escalated, "signal_hosts": len(profiles),
                "executed": False, "finding_promoted": False,
                "basis": "offline captured/source tells and declared shared-writer edges, not a race result"}

    def escalate(self, event_id):
        row = self.db.execute("SELECT * FROM workflow_events WHERE id=?", (event_id,)).fetchone()
        if not row or row["view"] != "logic" or row["outcome"] != "negative-for-variant" or \
                row["control"] in ("", "unknown"):
            return None
        wf, inv = self.model.current_invariant(row["wf_key"], row["inv_key"])
        if not inv or inv["predicate"]["type"] not in CONCURRENCY_RELEVANT or \
                self.model.event_state(dict(row))[0] == "stale":
            return None
        writers = [o for o in self.model.operations(wf["id"]) if inv["resource"] in
                   set().union(*(set(o["touches"][k]) for k in ("writes", "consumes", "publishes", "enqueues")))]
        if len(writers) < 2 or not self.model.resources(wf["id"])[inv["resource"]]["shared"]:
            return None
        env = {"schema": 1, "workflow": wf["wf_key"], "invariant": inv["inv_key"],
               "context": row["context_id"], "family": "RC-08", "resource": inv["resource"],
               "members": [{"operation": op["op_key"], "context": row["context_id"],
                            "intent": f"writer-{op['op_key']}"} for op in writers[:8]],
               "order_matters": True, "source_event": row["id"],
               "surviving_control": row["control"]}
        result = self.declare(env)
        return result["scenario_id"] if not result["unchanged"] else None

    def _signals(self):
        profiles = defaultdict(list)
        scope = self.model.ctx.scope
        for a in self.model.ctx.store.assets("endpoint")[:3000]:
            if not scope.is_in(a["value"]):
                continue
            host = host_of(a["value"])
            for word in sorted(set(m.group(0).lower() for m in SIGNALS.finditer(
                    urlsplit(a["value"]).path.replace("_", "-").replace("-", "/")))):
                profiles[host].append({"kind": "path-vocabulary", "tell": word, "source": f"asset:{a['id']}"})
            for tag in a["attrs"].get("tech", []) + a["attrs"].get("technologies", []):
                for label, pat in STACK_TELLS:
                    if pat.search(str(tag)):
                        profiles[host].append({"kind": "stack", "tell": label, "source": f"asset:{a['id']}"})
        for r in self.db.execute("SELECT id,url,method,status,resp_headers FROM requests "
                                 "ORDER BY id DESC LIMIT 3000"):
            if not scope.is_in(r["url"]):
                continue
            host = host_of(r["url"])
            headers = json.loads(r["resp_headers"] or "{}")
            for key in headers:
                if key.lower().startswith("x-ratelimit-") or key.lower() == "x-request-id":
                    profiles[host].append({"kind": "response-header", "tell": key.lower(),
                                           "source": f"request:{r['id']}"})
            if r["method"] in ("POST", "PUT", "PATCH") and r["status"] in (200, 201, 202) and \
                    not any(k.lower() == "cache-control" for k in headers):
                profiles[host].append({"kind": "response-header", "tell": "cache-control-unseen",
                                       "source": f"request:{r['id']}"})
        for a in self.model.ctx.store.assets("js")[:100]:
            if not scope.is_in(a["value"]):
                continue
            host = host_of(a["value"])
            for r in self.db.execute("SELECT id,body_sha256 FROM requests WHERE url=? ORDER BY id DESC LIMIT 3",
                                     (a["value"],)):
                if not r["body_sha256"]:
                    continue
                path = self.model.ctx.store.bodies_dir / r["body_sha256"]
                if not path.is_file() or path.stat().st_size > 5_000_000:
                    continue
                blob = path.read_bytes()
                for label, pat in JS_TELLS:
                    if pat.search(blob):
                        profiles[host].append({"kind": "client-js", "tell": label,
                                               "source": f"request:{r['id']}"})
        self.db.execute("DELETE FROM signal_profiles")
        for host, tells in profiles.items():
            # No HTTP/2 inference from a header or JS; explicit stored tech tag only.
            unique = list({(t["kind"], t["tell"], t["source"]): t for t in tells}.values())[:100]
            http2 = "yes" if any(a["attrs"].get("http2_supported") is True for a in
                                  self.model.ctx.store.assets("endpoint")[:3000]
                                  if host_of(a["value"]) == host and scope.is_in(a["value"])) \
                    else "unknown"
            self.db.execute("INSERT INTO signal_profiles VALUES(?,?,?,?,?)",
                            (host, json.dumps(unique), http2, len(unique), now()))
        self.db.commit()
        return profiles

    def profile(self, host):
        host = host_of(host) if "://" in host else host.lower().rstrip(".")
        row = self.db.execute("SELECT * FROM signal_profiles WHERE host=?", (host,)).fetchone()
        tells = json.loads(row["tells"]) if row else []
        def in_current_scope(tell):
            kind, _, source_id = tell["source"].partition(":")
            if kind not in ("asset", "request") or not source_id.isdecimal():
                return False
            table, column = ("assets", "value") if kind == "asset" else ("requests", "url")
            source = self.db.execute(f"SELECT {column} FROM {table} WHERE id=?", (int(source_id),)).fetchone()
            return bool(source and self.model.ctx.scope.is_in(source[column]))
        active = [t for t in tells if in_current_scope(t)]
        if row and not active:
            self.db.execute("DELETE FROM signal_profiles WHERE host=?", (host,))
            self.db.commit()
        return {"host": host, "tells": active, "score": len(active),
                "http2_supported": row["http2"] if row and active else "unknown",
                "basis": "offline tells only, not evidence of a protected effect", "executed": False,
                "finding_promoted": False}

    def plan(self, context=None, case=None, limit=25):
        if type(limit) is not int or not 1 <= limit <= 100 or case and case not in CASES:
            raise ValueError("plan limit 1..100 and case RC-01..RC-21 required")
        rows = []
        for s in self.db.execute("SELECT * FROM race_scenarios ORDER BY id"):
            if (context and s["context_id"] != context) or (case and s["family"] != case):
                continue
            wf, inv = self.model.current_invariant(s["wf_key"], s["inv_key"])
            if not inv:
                continue
            members = self._members(s["id"])
            ops = self._ops(wf, members)
            ctx = self.model.context(s["context_id"])
            modes = ("R", "L") if s["family"] in LAB_ONLY else ("R", "L", "C-P")
            ready, reason = self.model.live_gate("race", s["family"], modes, ctx,
                                                  wf, inv, ops, concurrent=True, channel="burp",
                                                  parallelism=len(members))
            if ready == "ready":
                ready, reason = "attestation-required", "operator fires an authorized gate; " \
                                "agent-driven synchronized sending remains M6-blocked"
            profile = self.profile(host_of(ops[0]["url"]))
            rows.append({"scenario": s["id"], "context": ctx["id"], "family": s["family"],
                         "invariant": s["inv_key"], "writers": [m["op_key"] for m in members],
                         "policy_status": wf["policy_status"], "readiness": ready, "reason": reason,
                         "signal_score": profile["score"], "crown_jewel": wf["crown_jewel"]})
        from .invariants import CROWN_RANK
        rows.sort(key=lambda r: (CROWN_RANK.get(r["crown_jewel"], 10), -r["signal_score"], r["scenario"]))
        return {"rows": rows[:limit], "total": len(rows), "truncated": len(rows) > limit,
                "executed": False, "finding_promoted": False,
                "agent_driven_synchronization": "blocked until M6"}

    def attest(self, env):
        """Import an operator declaration after a group; count all possible sends once."""
        _strict(env, "operator attestation", required=("schema", "scenario", "label", "tool", "engine",
                                                       "version", "protocol", "gate", "operator", "sent",
                                                       "retries", "requests", "connections", "members",
                                                       "artifact"))
        if type(env["schema"]) is not int or env["schema"] != 1:
            raise ValueError("unsupported attestation schema")
        s = self._scenario(env["scenario"])
        wf, inv = self.model.current_invariant(s["wf_key"], s["inv_key"])
        members = self._members(s["id"])
        ops = self._ops(wf, members)
        hosts = {host_of(op["url"]) for op in ops}
        if len(hosts) != 1:
            raise ValueError("operator attestation currently supports one scoped host per group")
        if s["family"] in LAB_ONLY or not self.model.resources(wf["id"])[s["resource"]]["disposable"] or \
                self.model.resources(wf["id"])[s["resource"]]["kind"] in ("money", "balance", "credit",
                                                                             "refund", "payout") or \
                inv["predicate"]["type"] in ("conservation-by-unit", "refund-capacity"):
            raise ValueError("M5a is owned nonfinancial disposable resources only")
        if any(self.model.context(m["context_id"])["basis"] != "captured" or
               self.model.context(m["context_id"])["account"] not in self.model.logic_config["owned_accounts"]
               for m in members):
            raise ValueError("every M5a member needs a captured, labelled owned test account")
        if env["protocol"] not in ("HTTP/1.1", "HTTP/2"):
            raise ValueError("operator attestation needs a supported, named protocol")
        if env["tool"] not in ("Burp Repeater", "Turbo Intruder"):
            raise ValueError("M5a is a named operator-run Burp/Turbo workflow")
        label = _text(env["label"], "label", 120, required=True)
        if not re.fullmatch(r"burp:[A-Za-z0-9._:-]{1,100}", label):
            raise ValueError("external receipt label must start burp:")
        for key in ("engine", "version", "gate", "operator"):
            if not isinstance(env[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}",
                                                              env[key]):
                raise ValueError(f"{key} must be a short tool/operator identifier")
        sent = _int(env["sent"], "sent", 2, 8)
        retries = _int(env["retries"], "retries", 0, 0)
        requests = _int(env["requests"], "requests", sent, sent)
        _int(env["connections"], "connections", 1, 30)
        if sent != len(members):
            raise ValueError("M5a requires one accounted send per declared writer; extras need M6")
        if sent > self.model.race_config["burst"]["max_parallelism"]:
            raise ValueError("group exceeds reviewed race burst")
        if not isinstance(env["members"], list) or len(env["members"]) != len(members):
            raise ValueError("attestation must cite one imported response reference per exact writer")
        refs = []
        for m, ref in zip(members, env["members"]):
            _strict(ref, "attested member", required=("operation", "context"), optional=("request_id",))
            if ref["operation"] != m["op_key"] or ref["context"] != m["context_id"]:
                raise ValueError("attested member does not bind the declared writer/context")
            if ref.get("request_id") is None:
                refs.append(None)  # potentially delivered; the external attempt remains spent
                continue
            receipt = self.model.receipts([{"basis": "imported-burp-capture",
                                            "request_id": ref["request_id"]}], "burp",
                                          [next(o for o in ops if o["op_key"] == m["op_key"])],
                                          self.model.context(m["context_id"]), "")[0]
            refs.append(receipt["request_id"])
        if len({rid for rid in refs if rid is not None}) != len([rid for rid in refs if rid is not None]):
            raise ValueError("one imported response cannot represent multiple members")
        if self.db.execute("SELECT 1 FROM race_attestations WHERE label=?", (label,)).fetchone():
            raise ValueError("external gate label already attested; reuse its ID for a linked run")
        if any((set(refs) - {None}) & (set(json.loads(row["members"])) - {None}) for row in
               self.db.execute("SELECT members FROM race_attestations")):
            raise ValueError("imported member receipts were already attested; do not charge twice")
        state, reason = self.model.live_gate("race", s["family"], ("R", "L", "C-P"),
                                              self.model.context(s["context_id"]), wf, inv, ops,
                                              concurrent=True, parallelism=sent, channel="burp")
        if state != "ready":
            raise ValueError(f"M5a is {state}: {reason}")
        budget = self.model.logic_config["budget"]
        used = self.model.usage()
        host = next(iter(hosts))
        if used["native_measured"] + used["external_declared"] + requests > budget["requests"] or \
                used["hosts"][host] + requests > budget["per_host"]:
            raise ValueError("attested attempts exceed the shared declared budget")
        data = self.model.artifacts([f"tool-attestation={env['artifact']}"])
        blob = data["tool-attestation"][1]
        if label.encode() not in blob or env["gate"].encode() not in blob:
            raise ValueError("attestation artifact must bind the receipt label and named gate")
        kept = self.model.keep(data)[0]
        cur = self.db.execute("INSERT INTO race_attestations(scenario_id,label,host,tool,engine,version,"
                              "protocol,gate,operator,sent,retries,requests,connections,members,path,sha256,created) "
                              "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (s["id"], label, host, env["tool"], env["engine"], env["version"],
                               env["protocol"], env["gate"], env["operator"], sent, retries, requests,
                                env["connections"], json.dumps(refs), kept[1], kept[2], now()))
        if None in refs:
            self.db.execute("INSERT INTO workflow_stops(host,stop_kind,event_id,created) VALUES(?,?,?,?)",
                            (host, "observer-lost", None, now()))
        self.db.commit()
        return {"attestation_id": cur.lastrowid, "label": label, "requests_declared": requests,
                "unresolved_members": refs.count(None),
                "basis": "operator-declared external-tool attempts; not recon-enforced or commit proof",
                "executed": False, "finding_promoted": False}

    def record(self, env):
        _strict(env, "race event", required=("scenario", "schedule", "outcome", "impact_tier", "members"),
                optional=("channel", "basis", "variant", "kind", "marker", "control_marker", "control",
                          "note", "attacker_gain", "root_key", "object_ref", "objects", "response_status",
                          "stop_trigger", "receipts", "artifacts", "facts", "projections", "control_projections",
                          "baseline_projections", "parent", "terminal", "chain_finding", "rubric",
                          "parallelism", "attempts", "successes", "window_evidence", "timing_quality",
                          "attestation", "next_play"))
        s = self._scenario(env["scenario"])
        wf, inv = self.model.current_invariant(s["wf_key"], s["inv_key"])
        if not inv or inv["resource"] != s["resource"]:
            raise ValueError("scenario invariant/resource revised; declare a new scenario")
        members = self._members(s["id"])
        ops = self._ops(wf, members)
        schedule = env["schedule"]
        if schedule not in SCHEDULES:
            raise ValueError("unsupported schedule")
        concurrent = schedule in ("concurrent", "fixed", "replay")
        if schedule == "replay" and (env.get("kind") != "replay" or type(env.get("parent")) is not int):
            raise ValueError("a concurrent replay needs a fresh observed parent and kind=replay")
        measures = ("parallelism", "attempts", "successes")
        measured = all(k in env for k in measures)
        if (any(k in env for k in measures) and not measured) or (not concurrent and measured) or \
                (concurrent and env["outcome"] in ("attempted", "pending", "observed", "negative-for-variant")
                 and not measured):
            raise ValueError("concurrent runs need parallelism, attempts and successes together")
        channel = env.get("channel", "lab")
        parallelism = attempts = successes = None
        if measured:
            parallelism = _int(env["parallelism"], "parallelism", 2, 8)
            attempts = _int(env["attempts"], "attempts", parallelism, 8)
            successes = _int(env["successes"], "successes", 0, attempts)
            if attempts != parallelism or parallelism > len(members) or \
                    (channel != "lab" and parallelism != len(members)):
                raise ValueError("one send per selected declared writer; only the owned lab may "
                                 "exercise a prefix of a 2..8 writer scenario")
            if env["outcome"] in ("blocked", "inconclusive", "skipped", "not-applicable") and \
                    not env.get("receipts"):
                raise ValueError("unexecuted review rows cannot declare measured attempts")
            if env["outcome"] == "observed" and not env.get("window_evidence", False) and successes == 0:
                raise ValueError("observed invariant effect needs at least one counted success")
            if env["outcome"] == "negative-for-variant" and successes:
                raise ValueError("a held control cannot count a forbidden effect as a success")
            runs = [dict(r) for r in self.db.execute("SELECT * FROM race_runs WHERE scenario_id=? AND "
                                                  "parallelism IS NOT NULL", (s["id"],))]
            bounds = self.model.race_config["burst"]
            if len(runs) >= bounds["max_runs"] or len({r["parallelism"] for r in runs} | {parallelism}) > bounds["max_points"]:
                raise ValueError("five-run/three-parallelism-point bound exceeded")
        window = env.get("window_evidence", False)
        if type(window) is not bool or window and (not measured or env["outcome"] != "observed" or
                                                    env.get("control") not in WINDOW_CONTROLS or successes):
            raise ValueError("window evidence is a concurrent held constraint, not an invariant breach")
        if env["outcome"] == "negative-for-variant" and concurrent and env.get("control") in WINDOW_CONTROLS and \
                "constraint" in str(env.get("note", "")).lower():
            raise ValueError("concurrency-time constraint evidence is observed window-evidence, not a negative")
        timing = env.get("timing_quality", "unknown")
        if timing not in ("unknown", "coarse-client", "operator-attested", "lab-monotonic", "authoritative-trace"):
            raise ValueError("unsupported timing quality")
        refs = env["members"]
        selected = members[:parallelism] if channel == "lab" and measured else members
        if not isinstance(refs, list) or len(refs) != len(selected):
            raise ValueError("run needs one reference for each selected declared member")
        member_refs = []
        for member, ref in zip(selected, refs):
            _strict(ref, "run member", required=("operation", "context", "intent"),
                    optional=("request_id", "marker", "clock_id", "commit_seq"))
            if (ref["operation"], ref["context"], ref["intent"]) != \
                    (member["op_key"], member["context_id"], member["intent"]):
                raise ValueError("run member does not bind exact writer, actor and intent")
            if concurrent and env["outcome"] in ("observed", "negative-for-variant") and \
                    not valid_marker(ref.get("marker")):
                raise ValueError("each measured member needs a fresh per-operation marker")
            if ref.get("request_id") is not None:
                basis = "imported-burp-capture" if channel == "burp" else "owned-loopback" if channel == "lab" else "target-http"
                if channel not in ("burp", "lab", "native"):
                    raise ValueError("member request binding unsupported for this channel")
                self.model.receipts([{"basis": basis, "request_id": ref["request_id"]}], channel,
                                    [next(o for o in ops if o["op_key"] == member["op_key"])],
                                    self.model.context(member["context_id"]), ref.get("marker", ""))
            member_refs.append(ref)
        attest_id = env.get("attestation")
        att = None
        if channel in LIVE_CHANNELS and concurrent:
            if s["family"] in LAB_ONLY or env["impact_tier"] in ("T2", "T3", "T4"):
                raise ValueError("this C-P family or terminal impact tier is lab-only / sequential-only")
            if channel != "burp" or type(attest_id) is not int:
                raise ValueError("agent-driven C-P is blocked; operator-run Burp needs an attestation")
            att = self.db.execute("SELECT * FROM race_attestations WHERE id=? AND scenario_id=?",
                                  (attest_id, s["id"])).fetchone()
            if not att or (measured and (att["sent"] != parallelism or att["requests"] != attempts)) or \
                    [r.get("request_id") for r in refs] != json.loads(att["members"]):
                raise ValueError("run does not reconcile its exact attested sends and imported member refs")
            if self.db.execute("SELECT 1 FROM race_runs WHERE attestation_id=?", (attest_id,)).fetchone():
                raise ValueError("one attested gate is one run; do not reuse its member sends")
            if _sha(local_bytes(self.model.ctx.campaign.root, att["path"])) != att["sha256"]:
                raise ValueError("attestation artifact changed before its run was recorded")
            if None in json.loads(att["members"]) and (env["outcome"] != "inconclusive" or
                    env.get("facts", {}).get("effected") != "unknown" or
                    env.get("stop_trigger") != "observer-lost"):
                raise ValueError("missing member response remains an inconclusive unknown effect with "
                                 "observer-lost stop until reconciled")
            receipts = env.get("receipts", [])
            if {tuple(sorted(r.items())) for r in receipts if isinstance(r, dict)} != \
                    {tuple(sorted({"basis": "external-declared", "label": att["label"],
                                    "requests": att["requests"]}.items()))} | \
                    {tuple(sorted({"basis": "imported-burp-capture", "request_id": rid}.items()))
                      for rid in json.loads(att["members"]) if rid is not None}:
                raise ValueError("race receipts must equal the attested external label and exact imported members")
        elif attest_id is not None:
            raise ValueError("attestation is for operator-run concurrent groups only")
        if concurrent and env["outcome"] in ("observed", "negative-for-variant") and \
                not all("request_id" in r for r in refs):
            raise ValueError("measured race effects need member request references")
        if concurrent and env["outcome"] in ("observed", "negative-for-variant") and \
                len({r["marker"] for r in refs if r.get("marker")}) != len(refs):
            raise ValueError("each member needs a distinct transport-attempt marker")
        if any("request_id" in r for r in refs):
            receipt_ids = {r["request_id"] for r in env.get("receipts", []) if "request_id" in r}
            if {r["request_id"] for r in refs if "request_id" in r} - receipt_ids:
                raise ValueError("every referenced member request must appear in event receipts")
        if env["impact_tier"] == "T4":
            # A downstream target-class proof alone cannot turn an unisolated
            # competing schedule into a race chain. Allow a fresh replay as the
            # fifth run when its parent already has both serial orders and a
            # fixed control; the model checks the replay's own fresh artifacts.
            if schedule == "replay":
                prior = [dict(row) for row in self.db.execute(
                    "SELECT e.*,r.schedule,r.sync_evidenced FROM race_runs r JOIN workflow_events e "
                    "ON e.id=r.event_id WHERE r.scenario_id=?", (s["id"],))]
                prior = [row for row in prior if self.model.event_state(row)[0] != "stale"]
                parent = next((row for row in prior if row["id"] == env.get("parent") and
                               row["schedule"] == "concurrent" and row["outcome"] == "observed" and
                               row["verdict"] == "violated" and row["sync_evidenced"]), None)
                def matching_control(row):
                    return (parent is not None and row["context_id"] == parent["context_id"] and
                            json.loads(parent["detail"]).get("baseline_projections") is not None and
                            row["object_ref"] != parent["object_ref"] and
                            row["outcome"] == "negative-for-variant" and
                            row["verdict"] == "satisfied" and row["control"] not in ("", "unknown") and
                            json.loads(row["detail"]).get("baseline_projections") ==
                            json.loads(parent["detail"]).get("baseline_projections"))
                controls = {row["schedule"] for row in prior if matching_control(row)}
                ready = parent is not None and {"serial-ab", "fixed"} <= controls and \
                    (not s["order_matters"] or "serial-ba" in controls) and \
                    not any(row["schedule"].startswith("serial-") and row["outcome"] == "observed"
                            and row["verdict"] == "violated" for row in prior)
            else:
                ready = self.causality(s["id"]).startswith("race-eligible")
            if not ready:
                raise ValueError("T4 race chain needs matched serial/fixed controls and synchronized "
                                 "owned-lab replay; unresolved schedule causality is not a chain proof")
        trace = None
        if channel == "lab" and measured and timing in ("lab-monotonic", "authoritative-trace"):
            traces = [a for a in env.get("artifacts", []) if isinstance(a, str) and
                      a.startswith("barrier-trace=")]
            if traces:
                trace = self.model.artifacts(traces)["barrier-trace"][1]
        sync_evidenced = bool(trace and all(valid_marker(ref.get("marker")) and
                                            ref["marker"].encode() in trace
                                            for ref in refs) and b"barrier release" in trace)
        clean = {k: v for k, v in env.items() if k not in ("scenario", "schedule", "members", "parallelism",
                                                          "attempts", "successes", "window_evidence",
                                                          "timing_quality", "attestation")}
        clean.update({"context": s["context_id"], "invariant": s["inv_key"], "case": s["family"]})
        extra = {"schedule": schedule, "member_refs": member_refs, "parallelism": parallelism,
                 "attempts": attempts, "successes": successes,
                 "success_ratio": f"{successes}/{attempts}" if measured else None,
                 "sync_declared": bool(att), "sync_evidenced": bool(sync_evidenced),
                 "timing_quality": timing, "attestation_id": attest_id}
        event = self.model.record("race", clean, case=s["family"],
                                  family_modes=("R", "L") if s["family"] in LAB_ONLY else
                                  (("R", "L", "C-P") if concurrent else ("R", "L", "C-S")),
                                   ops=self._ops(wf, selected), extra=extra,
                                   window_evidence=window, concurrent=concurrent,
                                  parallelism=parallelism, scenario_id=s["id"], prepaid=bool(att))
        self.db.execute("INSERT INTO race_runs(event_id,scenario_id,schedule,parallelism,attempts,successes,"
                        "window_evidence,timing_quality,sync_declared,sync_evidenced,attestation_id,members,created) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (event["event_id"], s["id"], schedule, parallelism, attempts, successes,
                         int(window), timing, int(bool(att)), int(bool(sync_evidenced)), attest_id,
                         json.dumps(member_refs), now()))
        self.db.commit()
        event.update({"causality": self.causality(s["id"]), "sync_evidenced": bool(sync_evidenced),
                      "success_ratio": extra["success_ratio"], "finding_promoted": False})
        return event

    def causality(self, scenario_id):
        rows = [dict(r) for r in self.db.execute("SELECT e.*,r.schedule,r.sync_evidenced,r.window_evidence "
                          "FROM race_runs r JOIN workflow_events e ON e.id=r.event_id WHERE r.scenario_id=?",
                          (scenario_id,))]
        valid = [r for r in rows if self.model.event_state(r)[0] != "stale"]
        if any(r["schedule"].startswith("serial-") and r["verdict"] == "violated" and
               r["outcome"] == "observed" for r in valid):
            return "sequential-primary; concurrency not isolated"
        trials = [r for r in valid if r["schedule"] == "concurrent" and r["outcome"] == "observed" and
                   r["verdict"] == "violated" and not r["window_evidence"]]
        if not trials:
            return "window-only" if any(r["window_evidence"] for r in valid) else "unresolved"
        s = self._scenario(scenario_id)
        def comparable(row):
            """Only compare the same declared starting state; controls need fresh objects."""
            detail = json.loads(row["detail"])
            first = json.loads(trials[0]["detail"])
            return (row["context_id"] == trials[0]["context_id"] and
                    detail.get("baseline_projections") is not None and
                    detail.get("baseline_projections") == first.get("baseline_projections") and
                    row["object_ref"] != trials[0]["object_ref"])
        serials = {r["schedule"] for r in valid if r["schedule"].startswith("serial-") and
                   comparable(r) and
                   r["outcome"] == "negative-for-variant" and r["verdict"] == "satisfied" and
                   r["control"] not in ("", "unknown")}
        fixed = any(r["schedule"] == "fixed" and r["outcome"] == "negative-for-variant" and
                    comparable(r) and
                     r["verdict"] == "satisfied" and r["control"] not in ("", "unknown") for r in valid)
        replay = any(r["schedule"] == "replay" and r["outcome"] == "observed" and
                     comparable(r) and r["parent_id"] in {t["id"] for t in trials} for r in valid)
        if {"serial-ab", "serial-ba" if s["order_matters"] else "serial-ab"} <= serials and \
                fixed and replay and any(r["sync_evidenced"] for r in trials):
            return "race-eligible for human validation (mechanism unconfirmed)"
        return "violated invariant; schedule causality unresolved"

    def verify(self):
        result = self.model.verify("race")
        invalid = list(result["invalid"])
        for r in self.db.execute("SELECT * FROM race_attestations ORDER BY id"):
            try:
                if _sha(local_bytes(self.model.ctx.campaign.root, r["path"])) != r["sha256"]:
                    raise ValueError("hash mismatch")
            except (ValueError, OSError):
                invalid.append({"attestation": r["id"], "reason": "missing/tampered"})
        for r in self.db.execute("SELECT * FROM race_runs ORDER BY id"):
            if not self.db.execute("SELECT 1 FROM workflow_events WHERE id=?", (r["event_id"],)).fetchone():
                invalid.append({"run": r["id"], "reason": "event missing"})
        result.update({"verified": result["verified"] and not invalid, "invalid": invalid[:100],
                       "attestations_checked": self.db.execute("SELECT count(*) FROM race_attestations").fetchone()[0],
                       "runs_checked": self.db.execute("SELECT count(*) FROM race_runs").fetchone()[0],
                       "finding_promoted": False})
        return result

    def status(self, limit=25):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit 1..100 required")
        runs = [dict(r) for r in self.db.execute("SELECT id,event_id,scenario_id,schedule,parallelism,attempts,"
                            "successes,window_evidence,timing_quality,sync_declared,sync_evidenced "
                            "FROM race_runs ORDER BY id DESC")]
        for run in runs:
            source = self.db.execute("SELECT * FROM workflow_events WHERE id=?",
                                     (run["event_id"],)).fetchone()
            run["evidence_state"] = self.model.event_state(dict(source))[0] if source else "stale"
        scenarios = [dict(r) for r in self.db.execute("SELECT id,wf_key,inv_key,context_id,family,resource "
                                             "FROM race_scenarios ORDER BY id")]
        measured = []
        for s in scenarios[:limit]:
            grouped = defaultdict(lambda: [0, 0, 0])
            for r in runs:
                if r["evidence_state"] != "stale" and r["scenario_id"] == s["id"] and \
                        r["schedule"] == "concurrent" and \
                        r["parallelism"] is not None:
                    point = grouped[r["parallelism"]]
                    point[0] += r["successes"]
                    point[1] += r["attempts"]
                    point[2] += 1
            points = [{"parallelism": p, "successes": totals[0], "attempts": totals[1],
                       "runs": totals[2], "ratio": f"{totals[0]}/{totals[1]}"}
                      for p, totals in sorted(grouped.items())]
            measured.append({**s, "causality": self.causality(s["id"]), "points": points,
                              "window_return_to_contract_at": None,
                              "window_basis": "counts at parallelism points do not establish an "
                                              "interleaving-window threshold; record matched schedule "
                                              "offsets and an owner trace before making that claim"})
        return {"scenarios": measured,
                "scenario_total": len(scenarios), "runs": runs[:limit], "run_total": len(runs),
                "usage": self.model.usage(), "verify": self.verify(), "stops": self.model.stops()[:limit],
                "obligations": self.model.obligations()[:limit], "chain_next": self.model.chain_next()[:limit],
                "agent_driven_synchronization": "blocked until M6", "executed": False,
                "finding_promoted": False}
