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
from .fields import field_claims_section
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
          _table(["class"] + list(COVERAGE_STATES),
                 [[k] + [v.get(s, 0) for s in COVERAGE_STATES] for k, v in sorted(by_cls.items())]),
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
          "\n## Worked rows\n",
          _table(["asset id", "endpoint/service", "class", "status", "note"],
                 [[c["asset_id"], c["asset_value"], c["bug_class"], c["status"], c["note"]]
                  for c in cov if c["status"] != "untested"])]

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
