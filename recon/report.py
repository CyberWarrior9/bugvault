"""Write recon state back into the vault campaign folder (plan4 §7: context compounds).

recon.md     surface inventory sorted by freshness, leads, policy-skipped work
coverage.md  endpoint x bug-class matrix (what is still untested)
intel.md     out-of-scope discoveries (never contacted)
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

from .csrf import report_rows as csrf_report_rows
from .authz import report_rows as authz_report_rows
from .fields import field_claims_section
from .ssti import report_rows as ssti_report_rows
from .upload import report_rows as upload_report_rows
from .jsledger import JsLedger
from .score import applicable_classes, freshness, is_inferred_only, sources, version_index
from .skillmap import SKILLS_DIR_REL, skills_for
from .store import COVERAGE_STATES, now


def _cell(v: Any, limit: int = 90) -> str:
    s = ", ".join(map(str, v)) if isinstance(v, (list, tuple, set)) else str(v if v is not None else "")
    s = s.replace("|", "\\|").replace("\n", " ")
    return s if len(s) <= limit else s[:limit - 1] + "…"


def _table(headers: List[str], rows: List[List[Any]]) -> str:
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def ranked_endpoints(store) -> List[Tuple[int, List[str], Dict[str, Any]]]:
    eps = store.assets("endpoint", in_scope=True)
    vidx = version_index(eps)
    ranked = []
    for e in eps:
        if is_inferred_only(e):
            continue
        s, why = freshness(e, vidx)
        ranked.append((s, why, e))
    ranked.sort(key=lambda x: (-x[0], x[2]["value"]))
    return ranked


def param_matrix(store) -> List[List[Any]]:
    rows = []
    by_ep: Dict[Tuple[int, str], List[Dict[str, Any]]] = defaultdict(list)
    for o in store.observations():
        by_ep[(o["endpoint_id"], o["method"])].append(o)
    for (eid, method), obs in sorted(by_ep.items()):
        n = len(obs)
        counts = Counter(p for o in obs for p in set(o["params"].get("query", []) +
                                                     o["params"].get("body", [])))
        if not counts:
            continue
        if n < 2:
            req, opt = "single sample: undetermined", sorted(counts)
        else:
            req = sorted(p for p, c in counts.items() if c == n)
            opt = sorted(p for p, c in counts.items() if c < n)
        rows.append([eid, method, store.get_asset(eid)["value"], n, req, opt])
    return rows


def idor_candidates(store) -> List[List[Any]]:
    rows = []
    by_ep: Dict[Tuple[int, str], Dict[str, Dict[str, set]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    for o in store.observations():
        if not o["account"]:
            continue
        for name, val in (o["params"].get("ids") or {}).items():
            by_ep[(o["endpoint_id"], o["method"])][o["account"]][name].add(val)
    for (eid, method), accts in sorted(by_ep.items()):
        if len(accts) < 2:
            continue
        names = set.intersection(*(set(v) for v in accts.values()))
        differing = [n for n in sorted(names)
                     if len({frozenset(accts[a][n]) for a in accts}) > 1]
        if differing:
            rows.append([eid, method, store.get_asset(eid)["value"], sorted(accts), differing])
    return rows


def context_param_matrix(store) -> List[List[Any]]:
    """Presence summaries never pool different principals, roles, tenants or workflow states."""
    groups = defaultdict(list)
    for observation in store.observations():
        context = observation["context"]
        key = (observation["endpoint_id"], observation["method"], observation["account"] or "",
               context.get("role", ""), context.get("tenant", ""), context.get("workflow_state", ""))
        groups[key].append(observation)
    rows = []
    for key, observations in sorted(groups.items()):
        counts = Counter(p for o in observations for p in set(o["params"].get("query", []) +
                                                              o["params"].get("body", [])))
        rows.append(list(key) + [len(observations), sorted(p for p, n in counts.items() if n == len(observations)),
                                sorted(p for p, n in counts.items() if n < len(observations))])
    return rows


def context_comparisons(store) -> List[Dict[str, Any]]:
    """Suggest explicit comparable capture pairs, not automatic authorization conclusions."""
    groups = defaultdict(list)
    for observation in store.observations():
        context = observation["context"]
        # Unknown roles/workflows cannot silently be treated as equivalent contexts.
        if not observation["account"] or not context.get("role") or not context.get("workflow_state"):
            continue
        key = (observation["endpoint_id"], observation["method"], context["role"], context["workflow_state"])
        groups[key].append(observation)
    rows = []
    for key, observations in sorted(groups.items()):
        principals = {(o["account"], o["context"].get("tenant", "")) for o in observations}
        if len(principals) >= 2:
            rows.append({"endpoint_id": key[0], "method": key[1], "role": key[2], "workflow_state": key[3],
                         "principals": sorted(principals), "observation_ids": [o["id"] for o in observations]})
    return rows


def write_reports(ctx) -> List[Path]:
    store, camp = ctx.store, ctx.campaign
    root = camp.root
    ts = now()
    jobs = store.jobs()
    jstate = Counter(j["state"] for j in jobs)
    kinds = Counter(a["kind"] for a in store.assets(in_scope=True))
    ranked = ranked_endpoints(store)
    facts = store.facts()
    js = JsLedger(ctx).status(limit=30)
    from .takeover import TakeoverLedger
    takeover = TakeoverLedger(ctx).status(limit=25)
    from .cloud import CloudLedger
    cloud = CloudLedger(ctx).status(limit=20)

    md = [f"---\ntags: [campaign, recon]\nprogram: {camp.program}\nmode: {camp.policy.mode}\n"
          f"generated: {ts}\n---\n",
          f"# Recon: {camp.program}\n",
          "> **Leads, not findings.** Nothing below is reportable until it is reproduced "
          "live and passes the validation gate. Generated by `python3 -m recon report`.\n",
          "## Summary\n",
          _table(["in-scope asset kind", "count"], sorted(kinds.items())),
          f"\nLogged successful HTTP exchanges (target + intel sources): **{store.request_count()}** · policy mode "
          f"**{camp.policy.mode}** · jobs: {dict(jstate)}\n"]

    skipped = [j for j in jobs if j["state"] == "skipped"]
    md.append("\n## Skipped by policy or missing tooling\n")
    md.append("Raise `policy.mode` in scope.json only if the program rules allow it; "
              "skipped jobs re-queue automatically on the next run.\n\n")
    md.append(_table(["job", "asset", "reason"],
                     [[j["kind"], j["asset_value"], j["note"]] for j in skipped[:80]]))

    md.append("\n## Takeover candidates (conditional, offline)\n")
    md.append("DNS/provider leads and parent trust references are not claimability or demonstrated "
              "impact. `recon takeover sync` updates the graph; no automatic resource claim.\n\n")
    md.append(_table(["candidate", "host", "record", "confidence", "conditional priority", "trust references"],
                     [[c["id"], c["name"], c["record_type"], c["data"].get("confidence"), c["priority"],
                       sorted({e["kind"] for e in c["trust_edges"]})] for c in takeover["candidates"]]))
    md.append(f"\nOpen cleanup receipts: **{len(takeover['cleanup_open'])}**; "
              f"integrity: **{takeover['integrity']['ok']}**; inventory/coverage incomplete.\n")
    md.append("\n## Cloud references (conditional, offline)\n")
    md.append("Static references, signed URLs, IAM-looking names and triage scores are leads, "
              "not resource ownership, effective permissions or findings. "
              "`recon cloud sync` parses stored in-scope bodies only; no cloud requests.\n\n")
    md.append(_table(["reference", "provider", "kind", "identifier", "priority", "signals"],
                     [[r["id"], r["provider"], r["resource_kind"], r["native_identifier"],
                       r["score"], r["triage_signals"]] for r in cloud["top"]]))
    md.append(f"\nReference rows: **{cloud['candidates']}**; offline generated host proposals: "
              f"**{cloud['generated_candidates']}** (unprobed, ownership unknown); "
              f"recorded events: **{cloud['events']}**; inventory/coverage incomplete; "
              "no finding promoted.\n")
    md.append("\n## Services\n")
    md.append(_table(["origin", "status", "title", "tech", "spa", "waf/cdn"],
                     [[s["value"], s["attrs"].get("status"), s["attrs"].get("title"),
                       s["attrs"].get("tech", []), s["attrs"].get("spa"),
                       s["attrs"].get("waf_cdn", [])]
                      for s in store.assets("service", in_scope=True)]))

    md.append("\n## Investigation priority\n")
    md.append("Heuristic investigation priority from observed source, authentication, version, "
              "and parameter signals. This does not establish that other hunters have not "
              "tested a surface. See recon/score.py.\n\n")
    md.append(_table(["score", "id", "endpoint", "methods", "params", "sources", "why",
                      "classes"],
                     [[s, e["id"], e["value"], e["attrs"].get("methods", []),
                       e["attrs"].get("params", []), sorted(sources(e)), why,
                       sorted(applicable_classes(e))]
                      for s, why, e in ranked[:80]]))

    sibs = [e for e in store.assets("endpoint", in_scope=True) if is_inferred_only(e)]
    md.append("\n## Old-version candidates (inferred, NOT requested)\n")
    md.append("Existence and authorization behavior are unknown. These are naming hypotheses only.\n\n")
    md.append(_table(["candidate", "newer version seen"],
                     [[e["value"], e["attrs"].get("sibling_of", [])] for e in sibs[:60]]))

    md.append("\n## Aggregate cross-account mapping leads (legacy, not context-equivalent)\n")
    md.append("Different object IDs per account are mapping leads, not IDOR evidence. "
              "Any later validation requires permitted controlled accounts and separate evidence.\n\n")
    md.append(_table(["id", "method", "endpoint", "accounts", "id params"],
                     idor_candidates(store)))

    md.append("\n## Aggregate parameter presence (not context-equivalent)\n")
    md.append("Presence in captured samples does not prove server-side required/optional rules.\n\n")
    md.append(_table(["id", "method", "endpoint", "samples", "always present", "sometimes present"],
                      param_matrix(store)[:120]))
    md.append("\n## Context-specific parameter presence\n")
    md.append("Contexts are not pooled. Even repeated presence does not prove a server-side rule.\n\n")
    md.append(_table(["family", "method", "account", "role", "tenant", "workflow", "samples",
                      "always present", "sometimes present"], context_param_matrix(store)[:200]))
    md.append("\n## Explicit comparison groups\n")
    md.append("Same known role/workflow, distinct account/tenant principals. Observation IDs link "
              "back to captures; these are comparison candidates, not evidence of a violation.\n\n")
    md.append(_table(["family", "method", "role", "workflow", "account/tenant", "observation ids"],
                     [[r["endpoint_id"], r["method"], r["role"], r["workflow_state"],
                       r["principals"], r["observation_ids"]] for r in context_comparisons(store)[:200]]))

    md.append("\n## Method-specific operations\n")
    md.append("Endpoint families group ID-shaped paths; operations preserve HTTP methods. "
              "Captured account/role/tenant contexts remain separate observations.\n\n")
    md.append(_table(["family id", "method", "endpoint", "parameters", "sources", "basis"],
                     [[o["endpoint_id"], o["method"], o["endpoint"], o["attrs"].get("params", []),
                        o["attrs"].get("sources", []), o["attrs"].get("bases", [])]
                      for o in store.operations()][:200]))
    md.append("\n## Captured context coverage (not security-test coverage)\n")
    contexts = Counter((o["endpoint_id"], o["method"], o["account"] or "",
                        o["context"].get("role", ""), o["context"].get("tenant", ""),
                        o["context"].get("workflow_state", "")) for o in store.observations())
    md.append(_table(["family", "method", "account", "role", "tenant", "workflow", "samples"],
                     [list(k) + [n] for k, n in sorted(contexts.items())][:200]))
    md.append("\n## Exact path variants\n")
    md.append("Families are scheduling groups, not proof that these paths have identical behavior. "
              "Query values are omitted; query names and exact paths are retained.\n\n")
    md.append(_table(["family", "method", "path", "query names"],
                     [[r["endpoint_id"], r["method"], r["path"], r["query_names"]]
                      for r in store.variants()][:200]))
    md.append("\n## Imported source provenance\n")
    md.append(_table(["import id", "format", "SHA-256", "context"],
                     [[r["id"], r["source"], r["sha256"], r["context"]] for r in store.imports()]))
    md.append("\nImport diagnostics reflect the most recent ingestion of each file/context.\n\n")
    md.append(_table(["import", "records/entries", "malformed", "unsupported", "duplicate records/samples"],
                     [[r["id"], r["stats"].get("records", r["stats"].get("entries", "")),
                       r["stats"].get("malformed", 0), r["stats"].get("unsupported", 0),
                       r["stats"].get("duplicate_records", r["stats"].get("duplicate_samples", 0))]
                      for r in store.imports()]))

    leads = [f for f in facts if f["confidence"] == "inferred" or f["kind"] in
             ("sourcemap", "runtime-gate", "dns")]
    md.append("\n## Leads\n")
    md.append(_table(["kind", "asset", "summary", "evidence"],
                     [[f["kind"], f["asset_value"], f["summary"], f["evidence"]]
                      for f in leads[:120]]))

    other = [f for f in facts if f not in leads]
    md.append("\n## Observations\n")
    md.append("Narrative observed/inferred labels below are not machine-checked response predicates.\n\n")
    md.append(_table(["kind", "asset", "summary"],
                     [[f["kind"], f["asset_value"], f["summary"]] for f in other[:120]]))

    from .factcheck import ResponseFacts
    md.append("\n## Response-backed predicate checks\n")
    md.append("Rechecked offline against stored responses. Supported means only the exact status/header/"
              "byte predicate is supported, not XSS, IDOR or other exploitability.\n\n")
    md.append(_table(["fact", "response", "outcome", "predicate claim", "reason", "capture basis"],
                     [[f["fact_id"], f["request_id"], f["outcome"], f["claim"], f["reason"], f["capture_basis"]]
                       for f in ResponseFacts(ctx).recent(50)]))
    md.append("\n## JS intelligence (stored responses; no endpoint tests)\n")
    md.append("The build/asset graph is bounded. Gaps are not negatives; imported captures are not "
              "fresh native responses. `js plan --packets` generates value-free work cards. "
              "`complete=false` blocks a coarse JS coverage closure.\n\n")
    md.append(f"Artifacts {js['artifacts']} · identified builds {js['builds']} · "
              f"integrity {'ok' if js['integrity']['ok'] else 'FAILED'} · "
              f"complete {str(js['complete']).lower()}.\n")
    md.append(f"Showing {min(150, len(js['stages']))}/{len(js['stages'])} stage rows and "
              f"{len(js['leads'])}/{js['leads_total']} ranked leads; a truncated report is not closure.\n")
    md.append(_table(["origin", "traffic-only", "precache-only", "import-map", "missing", "out-of-scope"],
                     [[o, len(g["traffic_only"]), g["precache_only"], g["importmap_resolved"],
                       len(g["pending"]), len(g["out_of_scope"])] for o, g in sorted(js["graphs"].items())]))
    md.append(_table(["build", "stage", "state", "reason"],
                     [[s["build_id"], s["stage"], s["state"], s["reason"]]
                      for s in js["stages"][:150]]))
    md.append(_table(["priority", "family", "lane", "subject", "why", "gain"],
                     [[l["priority"], l["family"], l["lane"], l["subject"], l["reason"], l["gain"]]
                      for l in js["leads"][:30]]))
    md.append("\n### Retained builds (not proof that a retired operation still exists)\n")
    md.append(_table(["origin", "build", "first", "last", "assets", "js_only", "zombie", "old hits"],
                     [[b["origin"], b["build_key"], b["first_seen"], b["last_seen"], b["artifact_count"],
                       b["js_only"], b["zombie"], b["retired_assets"]]
                      for b in JsLedger(ctx).builds()["builds"][:100]]))
    failed = [j for j in jobs if j["state"] == "failed"]
    md.append("\n## Failed jobs\n")
    md.append(_table(["job", "asset", "error"],
                     [[j["kind"], j["asset_value"], j["note"]] for j in failed[:60]]))

    # ---------------- coverage.md
    cov = store.coverage()
    by_cls: Dict[str, Counter] = defaultdict(Counter)
    for c in cov:
        by_cls[c["bug_class"]][c["status"]] += 1
    score_of = {e["id"]: s for s, _, e in ranked}
    untested = sorted((c for c in cov if c["status"] == "untested"),
                      key=lambda c: (-score_of.get(c["asset_id"], 0), c["asset_value"]))
    csrf = csrf_report_rows(ctx)
    ssti = ssti_report_rows(ctx)
    authz = authz_report_rows(ctx)
    upload = upload_report_rows(ctx)
    from .logic import LogicLedger
    from .race import RaceLedger
    logic_ledger, race_ledger = LogicLedger(ctx), RaceLedger(ctx)
    logic_summary, race_summary = logic_ledger.status(25), race_ledger.status(25)
    logic_plan, race_plan = logic_ledger.plan(limit=25), race_ledger.plan(limit=25)
    open_assets = {asset for wf in logic_ledger.model.workflows()
                   for asset in logic_ledger.model.operation_assets(wf)}
    coarse_workflow = logic_ledger.model.coarse_conflicts(open_assets)
    js_coarse = [c for c in cov if c["bug_class"] == "js-bundle" and
                 c["status"] != "untested" and not js["complete"]]
    cv = [f"---\ntags: [campaign, coverage]\nprogram: {camp.program}\ngenerated: {ts}\n---\n",
          f"# Coverage: {camp.program}\n",
           "Coarse endpoint-family × bug-class backlog. Recon seeds `untested` rows only; "
           "manual status changes are not independently verified. This matrix does not certify "
           "method/role/tenant/workflow security-test completeness. Update a row with:\n\n"
          "`python3 -m recon cov <campaign> <asset_id> <class> "
          "<tested|confirmed|refuted|n-a|queued> --note \"...\"`\n",
          f"The `skill` column names the skill in `{SKILLS_DIR_REL}/` to load before testing "
          "the row (primary first). Skills are instructions, not test results.\n",
           "## By class\n",
           "Takeover rows are host/zone investigation backlogs. A coarse status never certifies "
           "all DNS record types, claimability, chains or cleanup; inspect `recon takeover status`.\n",
           _table(["class"] + list(COVERAGE_STATES),
                  [[k] + [v.get(s, 0) for s in COVERAGE_STATES] for k, v in sorted(by_cls.items())]),
           "\n## JS bundle coverage\n",
           "Per-service JS rows remain open while `recon js status` reports unresolved asset, "
           "role, stage or top-band rung work. Coarse statuses cannot override that.\n",
           _table(["identified builds", "artifacts", "integrity", "complete"],
                  [[js["builds"], js["artifacts"], js["integrity"]["ok"], js["complete"]]]),
           _table(["origin", "js_only", "zombie", "traffic-only"],
                  [[o, len(js["sets"].get(o, {}).get("js_only", [])),
                    len(js["sets"].get(o, {}).get("zombie", [])), len(g["traffic_only"])]
                   for o, g in sorted(js["graphs"].items())]),
           _table(["coarse asset", "status", "contradiction"],
                  [[c["asset_value"], c["status"], "JS ledger still incomplete"] for c in js_coarse]),
          f"\n## Untested, freshest first ({len(untested)} rows)\n",
          _table(["asset id", "endpoint/service", "class", "why applicable", "skill"],
                 [[c["asset_id"], c["asset_value"], c["bug_class"], c["reason"],
                   skills_for(c["bug_class"]) or "-"]
                  for c in untested[:200]]),
          "\n## Module coverage claims\n",
          "Per-module parameter-coverage claims (field-ledger trigger matrix). A `full` "
          "claim is accepted by the engine only when every trigger cell is captured or "
          "n-a; `partial` was stamped automatically because cells were missing. "
          "Missing cells are named.\n",
           _table(["module", "claim", "missing triggers", "updated"],
                  field_claims_section(ctx)),
           "\n## Access-control and mass-assignment cases\n",
           "Offline exact-operation/context worklist (`recon authz plan/status`). "
           "A sent field is not an accepted field: use `recon fields diff` for declared/sent "
           "leads. `observed` is operator evidence, not an independently confirmed finding. "
           "Declared request counts do not enforce external traffic budgets.\n",
           f"Visible {authz['visible']}/{authz['total']} targets; "
           f"truncated {authz['truncated']}; artifact integrity "
           f"{'ok' if authz['artifact_integrity'] else 'FAILED'}; "
           f"current evidence {'yes' if authz['verified'] else 'no (stale/invalid)'}; "
           f"states {authz['totals']}.\n",
           _table(["target", "context", "case", "state/readiness"], authz["open"]),
           *( ["\n### Coarse authorization rows with open case work\n",
               _table(["asset", "class", "coarse status"], authz["coarse"])]
              if authz["coarse"] else [] ),
           "\n## File-upload lifecycle cases\n",
           "Offline sink × context × case worklist (`recon upload plan/status`). Accepted, "
           "stored, processed, served and executed are separate artifact-backed facts; a 201, "
           "thumbnail or callback is not execution. `impact-demonstrated` is operator evidence "
           "for review, not a confirmed finding. Declared Burp/browser/scanner counts are not "
           "measured traffic.\n",
           f"Visible {upload['visible']}/{upload['total']} sinks; artifact integrity "
           f"{'ok' if upload['artifact_integrity'] else 'FAILED'}; current evidence "
           f"{'yes' if upload['verified'] else 'no (stale/invalid)'}; states {upload['totals']}.\n",
           _table(["sink", "context", "case", "state/readiness"], upload["open"]),
           *(["\n### Upload objects awaiting cleanup\n",
              _table(["event", "host", "objects", "retention deadline", "overdue"], upload["cleanup"])]
             if upload["cleanup"] else []),
           *(["\n### Stopped upload hosts\n",
              _table(["host", "stop", "event"], upload["stopped"])] if upload["stopped"] else []),
           *(["\n### Coarse file-upload rows with open case work\n",
              _table(["asset", "coarse status"], upload["coarse"])] if upload["coarse"] else []),
           "\n## CSRF action coverage\n",
          "Per-origin action x context x case ledger (`python3 -m recon csrf status`). "
          "Fieldless actions, GET mutations, GraphQL operations and realtime handshakes are "
          "actions of their own; open = untested, in progress or reopened by a changed "
          "capture. A coarse `csrf` row above never closes open action cases. Work the next "
          "cases with `python3 -m recon csrf plan <campaign> --action <id>`.\n",
          _table(["origin", "actions", "captured", "declared only", "contexts", "open cases",
                  "observed", "negative", "blocked/inconclusive", "stale"], csrf["hosts"]),
          "\n### Next CSRF cases\n",
          _table(["action", "context", "target", "priority", "case", "readiness",
                  "open variants"], csrf["next"]),
          *(["\n### Coarse rows contradicted by open action cases\n",
             _table(["asset id", "coarse status", "open action cases"], csrf["coarse"])]
            if csrf["coarse"] else []),
           "\n## SSTI input × render-surface evidence\n",
            "Each set is scoped to one field context; submission, later views, email and exports "
            "remain independent. Confirmed here means two inert arithmetic evaluations and a "
            "literal control with stored submission receipts, not code execution or a finding. "
            "Missing probes are work, not a negative verdict. Artifacts and later responses "
            "still require an operator to verify causality and account ownership.\n",
            f"Audited {ssti['limits']['audited_sets']}/{ssti['limits']['total_sets']} sets; "
            f"displayed {ssti['limits']['visible_surfaces']}/"
            f"{ssti['limits']['total_audited_surfaces']} audited surfaces and "
            f"{ssti['limits']['visible_candidates']}/"
            f"{ssti['limits']['total_candidates_in_first_1000_endpoints']} candidate gaps "
            "(candidate scan covers at most 1,000 endpoints). A truncated report is not "
            "a complete coverage audit.\n",
           _table(["host", "asset", "field", "account", "role", "tenant", "workflow", "set",
                   "surface", "kind", "confirmed syntax family", "depth rungs proven",
                   "severity ceiling", "missing probes", "integrity"],
                  ssti["surfaces"]),
           "\n### SSTI inputs without a probe set\n",
           _table(["asset", "endpoint", "gap", "next action"], ssti["candidates"]),
           "\n### Next SSTI probes on open surfaces\n",
            _table(["set", "surface", "kind", "missing probe IDs"], ssti["next"]),
           "\n### Coarse SSTI rows contradicted by open input/surface work\n",
            _table(["asset", "coarse status", "open surfaces or gap"], ssti["coarse"]),
            "\n## Business-invariant and race evidence (offline views)\n",
            "`logic` and `race` share one workflow/invariant contract. An anomaly is not an adjudicated "
            "rule; a lab event is not target proof. An operator-attested gate is not agent-driven "
            "synchronization. Neither view sends traffic or promotes findings.\n",
            f"Logic observations {logic_summary['observation_total']}, events "
            f"{logic_summary['event_total']}; race scenarios {race_summary['scenario_total']}, "
            f"runs {race_summary['run_total']}; verification "
            f"logic={logic_summary['verify']['verified']}, race={race_summary['verify']['verified']}.\n",
            f"Historical stale events logic={len(logic_summary['verify']['stale'])}, "
            f"race={len(race_summary['verify']['stale'])}; unresolved obligations "
            f"{len(logic_summary['obligations'])}. Lists below are capped at 25.\n",
            _table(["workflow", "context", "invariant", "policy", "readiness"],
                   [[r["workflow"], r["context"], r["invariant"], r["policy_status"], r["readiness"]]
                    for r in logic_plan["rows"]]),
            _table(["scenario", "case", "context", "policy", "readiness"],
                   [[r["scenario"], r["family"], r["context"], r["policy_status"], r["readiness"]]
                    for r in race_plan["rows"]]),
            *( ["\n### Coarse BL/race statuses cannot close open exact cases\n",
                 _table(["asset", "class", "coarse status"], coarse_workflow)]
               if coarse_workflow else [] ),
            "\n## Worked rows\n",
          _table(["asset id", "endpoint/service", "class", "status", "note"],
                 [[c["asset_id"], c["asset_value"], c["bug_class"], c["status"], c["note"]]
                  for c in cov if c["status"] != "untested"])]

    # Bounded, sanitized review views; neither journal schedules any target work.
    from .cache_review import CacheReview
    from .http_review import HttpReview
    cache_reviews = CacheReview(ctx).status(limit=50)
    framing_reviews = HttpReview(ctx).status(limit=50)
    from .rce import RceLedger
    rce_reviews = RceLedger(ctx).status(limit=50)
    cv += ["\n## Cache capture and isolation reviews\n",
           "Offline captures, behavior/layer profiles and per-attempt isolation receipts. "
           "Unknown facets do not inherit from neighboring routes. Source-supported is an "
           "operator observation, not verified isolation or permission to prime a key. "
           "Raw headers, query values and bodies remain in private evidence. "
           f"Visible {cache_reviews['visible']}/{cache_reviews['total']}; "
           f"truncated={cache_reviews['truncated']}.\n",
           _table(["id", "kind", "origin", "method", "state", "integrity"],
                  [[r["id"], r["kind"], r.get("origin", "-"), r.get("method", "-"),
                    r.get("state", "observation-only"),
                    "invalid/stale" if r["integrity_issues"] else "hashes-current"]
                   for r in cache_reviews["rows"]]),
           "\n## HTTP framing capture reviews\n",
           "Local HTTP/1 lint only. Rejected framing does not establish parser disagreement, "
           "connection reuse, a cross-request effect or request smuggling. No sender, "
           "automatic finding or coverage closure is implemented. "
           f"Visible {framing_reviews['visible']}/{framing_reviews['total']}; "
           f"truncated={framing_reviews['truncated']}.\n",
           _table(["id", "origin", "verdict", "issue codes", "integrity"],
                  [[r["id"], r["origin"], r["verdict"], r["issues"],
                    "invalid/stale" if r["integrity_issues"] else "hashes-current"]
                   for r in framing_reviews["rows"]]),
           "\n## RCE sink and owned-lab evidence reviews\n",
           "Source-supported candidates are not proven reachable deployments; lab receipts "
           "are only eligible for independent validator review, never target findings. "
           "No traffic, payload generator or automatic coverage closure. "
           f"Visible {rce_reviews['visible']}/{rce_reviews['total']}; "
           f"truncated={rce_reviews['truncated']}.\n",
           _table(["id", "kind", "family", "origin", "state/qualification", "integrity"],
                  [[r["id"], r["kind"], r["family"], r["origin"],
                    r.get("assessment", {}).get("assessment", "source-supported" if r.get("qualified")
                                                     else "unqualified-lead"),
                    "invalid/stale" if r["integrity_issues"] else "hashes-current"]
                   for r in rce_reviews["rows"]])]

    # ---------------- intel.md
    intel = store.assets("intel")
    it = [f"---\ntags: [campaign, intel]\nprogram: {camp.program}\ngenerated: {ts}\n---\n",
          f"# Out-of-scope intel: {camp.program}\n",
          "Seen during recon, **never contacted**. Check whether any of these are actually "
          "in the program's scope (acquisitions, API hosts) before adding them to scope.json.\n\n",
          _table(["value", "sources", "notes"],
                 [[a["value"], a["attrs"].get("sources", []), a["attrs"].get("notes", [])[:3]]
                  for a in intel[:400]])]

    paths = []
    for name, body in (("recon.md", md), ("coverage.md", cv), ("intel.md", it)):
        p = root / name
        p.write_text("\n".join(body), encoding="utf-8")
        paths.append(p)
    from .findings import write_findings
    paths.append(write_findings(ctx, ts))
    return paths
