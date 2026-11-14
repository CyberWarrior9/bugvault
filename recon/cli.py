"""python3 -m recon <command> ...

  init <campaign> --seed example.com [--seed https://app.example.com] [--mode passive]
  check <campaign> <url> [<url> ...]        is this URL in scope? (and why not)
  run <campaign> [--max-jobs N] [--rerun KIND]
  import-har <campaign> <file.har> --account alice
  report <campaign>                          rewrite recon.md / coverage.md / intel.md
  cov <campaign> <asset_id> <class> <status> [--note TEXT]
  status <campaign>                          job queue summary
  lookup <campaign> [--kev-file F] [--no-sploitus] [--no-searchsploit] [--no-kev]
                                             versions -> public exploits / KEV -> leads
  finding add|move|link|list <campaign> ...  lead -> confirmed -> impact-proven -> reported -> outcome
  brief <campaign> [--role hunter]           render pre-authorized agent prompts into agents/
  recall <campaign> <query> [--limit N]      offline row/import-linked lexical recall
  plan <campaign> [--asset-id ID]           export bounded context; no model calls
  plan <campaign> --proposal F [--apply]    validate external intents; optionally enqueue only
  responses <campaign> [--limit N]        list stored HTTP response IDs (offline)
  fact check|verify|list <campaign> ...    deterministic response-backed predicates
  ssrf plan|record|status|correlate <campaign> --asset-id ID ...   offline workflow/evidence
  fields sync|show|record|canary|trace|matrix|na|claim|fingerprint|packet|payload|blind <campaign>
                                              field ledger, canary map, trigger-matrix gate,
                                              context packets and blind-XSS correlation
  waf plan|observe|record|show <campaign>     per-host WAF/filter profiles (offline)
  import-burp <campaign> <file> [--account A] Burp XML/JSON export or one raw request (offline)
  import-openapi <campaign> <spec.json>       OpenAPI 3 / Swagger 2 declared fields (offline)
  chain status|add|realism <campaign> [--file F]  cross-class todolist/lineage + realism gate
  csrf sync|plan|record|status|verify <campaign>  CSRF action x context x case ledger (offline)
  send <campaign> <url> [--method M] [--header 'K: V'] [--json J | --form k=v | --data D]
                                             one request through the scoped client; prints request_id

<campaign> is a name under vault/10-Campaigns/ or a path to a folder with scope.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .campaign import Campaign, ConfigError, HTTP_METHODS, MODES, OutOfScope, PolicyViolation, scope_template

REPO = Path(__file__).resolve().parents[1]
CAMPAIGNS = REPO / "vault" / "10-Campaigns"


def campaign_dir(name: str) -> Path:
    p = Path(name)
    if (p / "scope.json").exists() or p.is_absolute() or name.startswith("."):
        return p
    return CAMPAIGNS / name


def cmd_init(a) -> int:
    root = campaign_dir(a.campaign)
    cfg = root / "scope.json"
    if cfg.exists():
        print(f"{cfg} already exists; edit it instead", file=sys.stderr)
        return 1
    template = scope_template(a.program or root.name, a.seed, a.mode, a.allow_method)
    root.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps(template, indent=2) + "\n")
    print(f"created {cfg}\nNext: copy the program's in/out-of-scope lists and rules into it, "
          f"pick policy.mode from the program rules, then: python3 -m recon run {a.campaign}")
    return 0


def _load(name: str):
    from .pipeline import Recon
    return Recon(Campaign.load(campaign_dir(name)))


def cmd_check(a) -> int:
    camp = Campaign.load(campaign_dir(a.campaign))
    rc = 0
    for u in a.urls:
        try:
            camp.scope.check(u)
            print(f"IN   {u}")
        except OutOfScope as e:
            print(f"OUT  {u}  ({e})")
            rc = 2
    return rc


def cmd_run(a) -> int:
    from .report import write_reports
    ctx = _load(a.campaign)
    if a.rerun:
        print(f"re-queued {ctx.store.rerun(a.rerun)} {a.rerun} job(s)")
    stats = ctx.run(max_jobs=a.max_jobs)
    print(f"run: {stats}")
    for p in write_reports(ctx):
        print(f"wrote {p}")
    return 0


def cmd_har(a) -> int:
    from .har import import_har
    from .report import write_reports
    ctx = _load(a.campaign)
    try:
        stats = import_har(ctx, Path(a.har), a.account, a.role, a.tenant, a.workflow_state)
        print(f"import: {stats}")
        print("queued JS from the HAR is parsed on the next `run` (mode permitting)")
        ctx.refresh_coverage()
        for p in write_reports(ctx):
            print(f"wrote {p}")
        return 2 if stats["malformed"] else 0
    finally:
        ctx.store.close()


def cmd_report(a) -> int:
    from .report import write_reports
    ctx = _load(a.campaign)
    ctx.refresh_coverage()
    for p in write_reports(ctx):
        print(f"wrote {p}")
    return 0


def cmd_cov(a) -> int:
    from .report import write_reports
    ctx = _load(a.campaign)
    ctx.store.get_asset(a.asset_id)
    ctx.store.set_coverage(a.asset_id, a.bug_class, a.status, a.note)
    write_reports(ctx)
    print(f"coverage[{a.asset_id}, {a.bug_class}] = {a.status}")
    return 0


def cmd_status(a) -> int:
    ctx = _load(a.campaign)
    jobs = ctx.store.jobs()
    print(f"mode={ctx.policy.mode} requests_sent={ctx.store.request_count()}")
    print(f"campaign_http_attempts={ctx.store.network_attempts()}/{ctx.policy.max_campaign_requests}")
    print(f"llm_agents=0 scheduler=1 handlers=8 imports={len(ctx.store.imports())} "
          f"endpoint_operations={len(ctx.store.operations())}")
    for (kind, state), n in sorted(Counter((j["kind"], j["state"]) for j in jobs).items()):
        print(f"  {kind:10} {state:8} {n}")
    return 0


def cmd_catalog(a) -> int:
    from .catalog import catalog, render_catalog
    data = catalog()
    print(json.dumps(data, indent=2) if a.json else render_catalog(data))
    return 0


def cmd_import(a) -> int:
    from .ingest import import_artifact
    from .report import write_reports
    ctx = _load(a.campaign)
    try:
        result = import_artifact(ctx, Path(a.artifact), a.format)
        ctx.refresh_coverage()
        write_reports(ctx)
        print(json.dumps(result, indent=2))
        print("Offline import only. Queued jobs execute only on an explicit `run`.")
        return 2 if result["malformed"] else 0
    finally:
        ctx.store.close()


def cmd_lookup(a) -> int:
    from .report import write_reports
    from .vulnintel import lookup
    ctx = _load(a.campaign)
    try:
        stats = lookup(ctx, kev_file=Path(a.kev_file) if a.kev_file else None,
                       use_kev=not a.no_kev, use_sploitus=not a.no_sploitus,
                       use_searchsploit=not a.no_searchsploit, refresh=a.refresh)
        print(f"lookup: {stats}")
        for p in write_reports(ctx):
            print(f"wrote {p}")
        return 0
    finally:
        ctx.store.close()


def cmd_finding(a) -> int:
    from .findings import Findings, write_findings
    ctx = _load(a.campaign)
    try:
        fx = Findings(ctx)
        if a.action == "add":
            fid, created = fx.add(a.title, a.bug_class, asset_id=a.asset, url=a.url,
                                  severity=a.severity, tech=a.tech or [], note=a.note)
            print(f"{'created' if created else 'exists'} finding #{fid} [lead]")
        elif a.action == "move":
            f = fx.move(a.id, a.stage, note=a.note, severity=a.severity,
                        replay=Path(a.replay) if a.replay else None,
                        control=Path(a.control) if a.control else None,
                        impact=Path(a.impact) if a.impact else None,
                        report=Path(a.report) if a.report else None)
            print(f"finding #{f['id']} -> {f['stage']}")
        elif a.action == "link":
            new = fx.link(a.src, a.relation, a.dst, a.note)
            print(f"#{a.src} --{a.relation}-> #{a.dst} {'linked' if new else '(already linked)'}")
        else:
            for f in fx.all(a.stage):
                print(f"#{f['id']:<4} {f['stage']:13} p={f['priority']:<3} {f['bug_class']:16} "
                      f"{f['severity'] or '-':8} {f['title']}")
        print(f"wrote {write_findings(ctx)}")
        return 0
    finally:
        ctx.store.close()


def cmd_brief(a) -> int:
    from .brief import ROLES, write_briefs
    camp = Campaign.load(campaign_dir(a.campaign))
    for p in write_briefs(camp, [a.role] if a.role else ROLES):
        print(f"wrote {p}")
    return 0


def cmd_recall(a) -> int:
    from .recall import recall
    ctx = _load(a.campaign)
    try:
        print(json.dumps(recall(ctx, a.query, a.limit), indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_plan(a) -> int:
    from .planning import review, snapshot
    ctx = _load(a.campaign)
    try:
        if a.proposal:
            result = review(ctx, Path(a.proposal), apply=a.apply)
        else:
            if a.apply:
                raise ValueError("--apply requires --proposal")
            result = snapshot(ctx, a.asset_id or [])
        print(json.dumps(result, indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_responses(a) -> int:
    ctx = _load(a.campaign)
    try:
        if not 1 <= a.limit <= 200:
            raise ValueError("response list limit must be 1..200")
        rows = ctx.store.db.execute("SELECT r.id,r.method,r.url,r.status,r.body_len,r.error,"
                                    "c.body_complete,c.basis FROM requests r LEFT JOIN response_capture c "
                                    "ON c.request_id=r.id ORDER BY r.id DESC LIMIT ?", (a.limit,))
        print(json.dumps([dict(r) for r in rows], indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_inputs(a) -> int:
    from .inputs import input_census
    ctx = _load(a.campaign)
    try:
        print(json.dumps(input_census(ctx, a.asset_id), indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_chain(a) -> int:
    from .chain import ChainLedger, load_plan
    ctx = _load(a.campaign)
    try:
        ledger = ChainLedger(ctx)
        if a.action == "add":
            plan = load_plan(a.file)
            plan_id = ledger.add(plan.get("name"), plan.get("description") or "",
                                 plan.get("steps"))
            print(json.dumps({"chain_id": plan_id, "name": plan.get("name"),
                              "basis": "custom chain recorded; steps resolve from findings only"},
                             indent=2))
        elif a.action == "realism":
            if a.outcome is None:
                print(json.dumps(ledger.realism(a.chain_name), indent=2))
            else:
                result = ledger.realism(a.chain_name, a.question, a.outcome, a.note or "")
                print(json.dumps(result, indent=2))
        else:
            print(json.dumps(ledger.overview(), indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_ssrf(a) -> int:
    from .ssrf import SSRFWorkflow, read_json
    ctx = _load(a.campaign)
    try:
        workflow = SSRFWorkflow(ctx)
        if a.action == "correlate":
            result = workflow.correlate(a.asset_id, read_json(a.bundle))
        else:
            context = read_json(a.context) if a.context else None
            if a.action == "record":
                result = workflow.record(a.asset_id, context, a.case, a.state, a.note,
                                         a.artifact or [], a.requests_declared)
            else:
                result = workflow.plan(a.asset_id, context)
        print(json.dumps(result, indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_fields(a) -> int:
    from .fields import FieldLedger
    ctx = _load(a.campaign)
    try:
        ledger = FieldLedger(ctx)
        if a.action == "sync":
            result = ledger.sync(a.asset_id)
        elif a.action == "show":
            result = ledger.show(a.asset_id, a.case, a.state)
        elif a.action == "record":
            result = ledger.record(a.asset_id, a.field, a.case, a.state, a.method,
                                   a.location, a.account, a.note or "", a.model or "",
                                   a.workflow or "")
        elif a.action == "canary":
            result = ledger.canary(a.asset_id, a.field, a.method, a.location,
                                   a.account, a.workflow or "")
        elif a.action == "trace":
            result = ledger.trace(a.marker)
        elif a.action == "matrix":
            result = ledger.matrix(a.module)
        elif a.action == "na":
            result = ledger.set_na(a.module, a.trigger, a.reason)
        elif a.action == "claim":
            result = ledger.claim(a.module, a.claim_state)
        elif a.action == "fingerprint":
            result = ledger.fingerprint(a.asset_id, a.kind, a.value, a.note or "")
        elif a.action == "packet":
            result = ledger.packet(a.asset_id, a.field, a.case)
        elif a.action == "payload":
            result = ledger.record_payload(a.file, a.model, a.provider or "", a.note or "")
        else:  # blind
            bundle = json.loads(Path(a.bundle).read_text()[:1_000_001])
            result = ledger.blind(a.asset_id, bundle)
        print(json.dumps(result, indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_csrf(a) -> int:
    from .csrf import CsrfLedger
    ctx = _load(a.campaign)
    try:
        ledger = CsrfLedger(ctx)
        if a.action == "sync":
            result = ledger.sync()
        elif a.action == "plan":
            result = ledger.plan(action_id=a.action_id, host=a.host, limit=a.limit)
        elif a.action == "record":
            result = ledger.record(
                a.context, a.case, a.state, variant=a.variant or "",
                attempt_kind=a.attempt_kind, initiator=a.initiator,
                initiator_origin=a.initiator_origin or "", delivery=a.delivery or "",
                preflight=a.preflight or "", browser=a.browser or "",
                prerequisite=a.prerequisite or "", artifacts=a.artifact or [],
                tool_refs=a.tool_ref or [], requests=a.requests, connections=a.connections,
                messages=a.messages, note=a.note or "")
        elif a.action == "verify":
            result = ledger.verify_artifacts()
        else:  # status
            result = ledger.status(host=a.host)
        print(json.dumps(result, indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_waf(a) -> int:
    from .waf import WAFProfiles
    ctx = _load(a.campaign)
    try:
        waf = WAFProfiles(ctx)
        if a.action == "plan":
            result = waf.plan(a.host)
        elif a.action == "observe":
            baseline_body = Path(a.baseline_body).read_bytes()[:2_000_000] \
                if a.baseline_body else b""
            probe_body = Path(a.probe_body).read_bytes()[:2_000_000] if a.probe_body else b""
            result = waf.observe(a.host, a.baseline_status, baseline_body, a.probe_status,
                                 probe_body, a.element, a.marker, reset=a.reset,
                                 baseline_headers=json.loads(a.baseline_headers)
                                 if a.baseline_headers else None,
                                 probe_headers=json.loads(a.probe_headers)
                                 if a.probe_headers else None)
        elif a.action == "record":
            result = waf.record(a.host, a.element, a.kind, a.paired_with, a.location,
                                a.content_type, a.outcome, a.marker, a.note or "")
        else:  # show
            result = waf.show(a.host)
        print(json.dumps(result, indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_import_burp(a) -> int:
    from .burp import import_burp
    from .report import write_reports
    ctx = _load(a.campaign)
    try:
        stats = import_burp(ctx, Path(a.file), a.account, a.role, a.tenant,
                            a.workflow_state, a.scheme)
        print(f"import: {stats}")
        print("header/cookie names were captured (values never stored); "
              "stored responses are searchable by `recon fields trace`")
        ctx.refresh_coverage()
        for p in write_reports(ctx):
            print(f"wrote {p}")
        return 2 if stats["malformed"] else 0
    finally:
        ctx.store.close()


def cmd_import_openapi(a) -> int:
    from .report import write_reports
    from .specs import import_openapi
    ctx = _load(a.campaign)
    try:
        stats = import_openapi(ctx, Path(a.spec))
        print(f"import: {stats}")
        print("declared fields are tagged spec_fields; `recon fields sync` turns "
              "them into ledger rows with exact locations")
        ctx.refresh_coverage()
        for p in write_reports(ctx):
            print(f"wrote {p}")
        return 2 if stats["malformed"] else 0
    finally:
        ctx.store.close()


def cmd_fact(a) -> int:
    from .factcheck import ResponseFacts
    ctx = _load(a.campaign)
    try:
        checker = ResponseFacts(ctx)
        if a.action == "check":
            if len(a.predicate) > 8000:
                raise ValueError("predicate exceeds 8000 characters")
            result = checker.add(a.response, json.loads(a.predicate), a.asset_id)
        elif a.action == "verify":
            result = checker.verify(a.id)
        elif a.action == "context":
            print(json.dumps(checker.require_supported(a.ids), indent=2))
            return 0
        else:
            print(json.dumps(checker.recent(a.limit), indent=2))
            return 0
        print(json.dumps(result, indent=2))
        return 0 if result["outcome"] == "supported" else 2
    finally:
        ctx.store.close()


def _send_body(a, max_bytes: int):
    given = [flag for flag, value in (("--data", a.data), ("--data-file", a.data_file),
                                      ("--json", a.json), ("--form", a.form)) if value is not None]
    if len(given) > 1:
        raise ValueError("use only one of --data, --data-file, --json, --form")
    if a.data is not None:
        return a.data.encode("utf-8"), a.content_type
    if a.data_file is not None:
        with open(a.data_file, "rb") as source:
            return source.read(max_bytes + 1), a.content_type
    if a.json is not None:
        json.loads(a.json)  # reject malformed JSON before anything is sent
        return a.json.encode("utf-8"), a.content_type or "application/json"
    if a.form is not None:
        from urllib.parse import urlencode
        pairs = []
        for item in a.form:
            key, sep, value = item.partition("=")
            if not sep or not key:
                raise ValueError("--form fields must be key=value")
            pairs.append((key, value))
        return urlencode(pairs).encode("ascii"), a.content_type or "application/x-www-form-urlencoded"
    return None, a.content_type


def cmd_send(a) -> int:
    """One request through ScopedClient: scope, method grant, rate, budgets, pinned egress."""
    import hashlib
    from .net import FetchError
    ctx = _load(a.campaign)
    try:
        method = a.method.upper()
        if not a.purpose.strip() or len(a.purpose) > 200:
            raise ValueError("--purpose must be 1..200 characters")
        if not 0 <= a.show_body <= 100_000:
            raise ValueError("--show-body must be 0..100000")
        headers = {}
        for item in a.header or []:
            name, sep, value = item.partition(":")
            if not sep or not name.strip() or any(c in item for c in "\r\n\x00"):
                raise ValueError("--header must be one 'Name: value' line")
            headers[name.strip()] = value.strip()
        body, content_type = _send_body(a, ctx.policy.max_body_bytes)
        if method in ("GET", "HEAD"):
            if body is not None:
                raise ValueError("GET/HEAD cannot carry a body; use a write method")
            resp = ctx.client.get(a.url, a.purpose, follow=not a.no_follow, headers=headers or None,
                                  method=method)
        else:
            resp = ctx.client.request(method, a.url, a.purpose, body=body, content_type=content_type,
                                      headers=headers or None)
        print(json.dumps({
            "request_id": resp.request_id, "method": method, "url": resp.url, "status": resp.status,
            "redirect_chain": resp.redirect_chain, "blocked_redirect": resp.blocked_redirect,
            "headers": resp.headers, "body_bytes": len(resp.body),
            "body_sha256": hashlib.sha256(resp.body).hexdigest(), "truncated": resp.truncated,
            "body_preview": resp.body[:a.show_body].decode("utf-8", "replace")}, indent=2))
        print(f"evidence: python3 -m recon fact check {a.campaign} --response {resp.request_id} "
              "--predicate '<JSON>'", file=sys.stderr)
        return 0
    except FetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        ctx.store.close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python3 -m recon", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("catalog", help="phases, tools, integrations and actual agent/guide counts")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_catalog)
    s = sub.add_parser("import", help="offline scanner-output import (never launches scans)")
    s.add_argument("campaign")
    s.add_argument("artifact")
    from .ingest import FORMATS
    s.add_argument("--format", choices=FORMATS, required=True)
    s.set_defaults(fn=cmd_import)
    s = sub.add_parser("init")
    s.add_argument("campaign")
    s.add_argument("--seed", action="append", required=True)
    s.add_argument("--program")
    s.add_argument("--mode", choices=MODES, default="passive")
    s.add_argument("--allow-method", action="append", type=str.upper, choices=sorted(HTTP_METHODS),
                   help="grant an additional HTTP method; repeatable; default GET/HEAD only; "
                        "other methods require active/loud mode and program permission")
    s.set_defaults(fn=cmd_init)
    s = sub.add_parser("check")
    s.add_argument("campaign")
    s.add_argument("urls", nargs="+")
    s.set_defaults(fn=cmd_check)
    s = sub.add_parser("run")
    s.add_argument("campaign")
    s.add_argument("--max-jobs", type=int, default=2000)
    s.add_argument("--rerun", help="re-queue every job of this kind (e.g. jsparse)")
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("import-har")
    s.add_argument("campaign")
    s.add_argument("har")
    s.add_argument("--account", required=True, help="canary account label, e.g. alice")
    s.add_argument("--role", default="")
    s.add_argument("--tenant", default="")
    s.add_argument("--workflow-state", default="")
    s.set_defaults(fn=cmd_har)
    s = sub.add_parser("report")
    s.add_argument("campaign")
    s.set_defaults(fn=cmd_report)
    s = sub.add_parser("cov")
    s.add_argument("campaign")
    s.add_argument("asset_id", type=int)
    s.add_argument("bug_class")
    s.add_argument("status")
    s.add_argument("--note")
    s.set_defaults(fn=cmd_cov)
    s = sub.add_parser("status")
    s.add_argument("campaign")
    s.set_defaults(fn=cmd_status)
    s = sub.add_parser("lookup", help="fingerprinted versions -> searchsploit/Sploitus/KEV leads")
    s.add_argument("campaign")
    s.add_argument("--kev-file", help="offline KEV JSON instead of the cached/fetched feed")
    s.add_argument("--no-kev", action="store_true")
    s.add_argument("--no-sploitus", action="store_true")
    s.add_argument("--no-searchsploit", action="store_true")
    s.add_argument("--refresh", action="store_true", help="explicitly retry cached/suppressed intel providers")
    s.set_defaults(fn=cmd_lookup)
    from .findings import RELATIONS, SEVERITIES, STAGES
    s = sub.add_parser("finding", help="finding lifecycle: add | move | link | list")
    fsub = s.add_subparsers(dest="action", required=True)
    f = fsub.add_parser("add")
    f.add_argument("campaign")
    f.add_argument("--title", required=True)
    f.add_argument("--class", dest="bug_class", required=True)
    f.add_argument("--url")
    f.add_argument("--asset", type=int)
    f.add_argument("--severity", choices=SEVERITIES)
    f.add_argument("--tech", action="append")
    f.add_argument("--note")
    f = fsub.add_parser("move")
    f.add_argument("campaign")
    f.add_argument("id", type=int)
    f.add_argument("stage", choices=STAGES)
    for opt in ("--replay", "--control", "--impact", "--report", "--note"):
        f.add_argument(opt)
    f.add_argument("--severity", choices=SEVERITIES)
    f = fsub.add_parser("link")
    f.add_argument("campaign")
    f.add_argument("src", type=int)
    f.add_argument("relation", choices=RELATIONS)
    f.add_argument("dst", type=int)
    f.add_argument("--note")
    f = fsub.add_parser("list")
    f.add_argument("campaign")
    f.add_argument("--stage", choices=STAGES)
    s.set_defaults(fn=cmd_finding)
    s = sub.add_parser("brief", help="render pre-authorized hunter/validator/reporter prompts")
    s.add_argument("campaign")
    s.add_argument("--role", choices=("hunter", "validator", "reporter"))
    s.set_defaults(fn=cmd_brief)
    s = sub.add_parser("recall", help="offline campaign-local recall with source references")
    s.add_argument("campaign")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=10)
    s.set_defaults(fn=cmd_recall)
    s = sub.add_parser("plan", help="offline bounded planning snapshot or proposal review; no model calls")
    s.add_argument("campaign")
    s.add_argument("--asset-id", action="append", type=int)
    s.add_argument("--proposal", help="external JSON proposal to validate")
    s.add_argument("--apply", action="store_true", help="enqueue validated known jobs; never execute them")
    s.set_defaults(fn=cmd_plan)
    s = sub.add_parser("responses", help="offline list of stored response IDs and capture completeness")
    s.add_argument("campaign")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(fn=cmd_responses)
    s = sub.add_parser("fact", help="check typed status/header/raw-byte facts against stored responses")
    facts = s.add_subparsers(dest="action", required=True)
    f = facts.add_parser("check")
    f.add_argument("campaign")
    f.add_argument("--response", type=int, required=True)
    f.add_argument("--asset-id", type=int)
    f.add_argument("--predicate", required=True, help="strict JSON predicate; see recon/README.md")
    f = facts.add_parser("verify")
    f.add_argument("campaign")
    f.add_argument("id", type=int)
    f = facts.add_parser("list")
    f.add_argument("campaign")
    f.add_argument("--limit", type=int, default=50)
    f = facts.add_parser("context")
    f.add_argument("campaign")
    f.add_argument("ids", type=int, nargs="+")
    s.set_defaults(fn=cmd_fact)
    s = sub.add_parser("chain", help="cross-class chain todolist over findings; offline, orders the hunt")
    actions = s.add_subparsers(dest="action", required=True)
    f = actions.add_parser("status", help="ready/waiting/proven steps for every chain")
    f.add_argument("campaign")
    f = actions.add_parser("add", help="record a custom chain from a validated JSON plan")
    f.add_argument("campaign")
    f.add_argument("--file", required=True, help='JSON {"name","description","steps":[{"class","goal"}]}')
    from .chain import REALISM_OUTCOMES, REALISM_QUESTIONS
    f = actions.add_parser("realism", help="record one answer of the three-question realism gate")
    f.add_argument("campaign")
    f.add_argument("chain_name")
    f.add_argument("question", choices=[q for q, _ in REALISM_QUESTIONS])
    f.add_argument("outcome", nargs="?", choices=REALISM_OUTCOMES,
                   help="omit to show the current answers")
    f.add_argument("--note")
    s.set_defaults(fn=cmd_chain)
    s = sub.add_parser("inputs", help="per-endpoint input census with probe receipts; read-only")
    s.add_argument("campaign")
    s.add_argument("--asset-id", type=int, required=True)
    s.set_defaults(fn=cmd_inputs)
    s = sub.add_parser("ssrf", help="offline SSRF matrix, case ledger and evidence correlation; sends no traffic")
    actions = s.add_subparsers(dest="action", required=True)
    from .ssrf import CASE_BY_ID, STATES
    for action in ("plan", "status", "record", "correlate"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--asset-id", type=int, required=True)
        if action == "correlate":
            f.add_argument("--bundle", required=True, help="normalized JSON; see hunt-ssrf references/evidence.md")
        else:
            f.add_argument("--context", required=action == "record", help="JSON file containing the exact test context")
        if action == "record":
            f.add_argument("--case", choices=sorted(CASE_BY_ID), required=True)
            f.add_argument("--state", choices=STATES, required=True)
            f.add_argument("--note", required=True)
            f.add_argument("--artifact", action="append", help="campaign-relative evidence file; repeatable")
            f.add_argument("--requests-declared", type=int, default=0, help="external count assertion, not shared budget enforcement")
    s.set_defaults(fn=cmd_ssrf)
    s = sub.add_parser("fields", help="field ledger, canary map, trigger-matrix gate, "
                                      "context packets, blind-XSS correlation; sends no traffic")
    actions = s.add_subparsers(dest="action", required=True)
    from .fields import CASES_BY_CLASS, CLAIMS, FINGERPRINT_KINDS, LOCATIONS, STATES, TRIGGERS
    _case_ids = sorted({c for cases in CASES_BY_CLASS.values() for c in cases})
    f = actions.add_parser("sync")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f = actions.add_parser("show")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f.add_argument("--case", choices=_case_ids)
    f.add_argument("--state", choices=STATES)
    f = actions.add_parser("record")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f.add_argument("--field", required=True)
    f.add_argument("--case", choices=_case_ids, required=True)
    f.add_argument("--state", choices=STATES, required=True)
    f.add_argument("--method", default="")
    f.add_argument("--location", choices=LOCATIONS, default="unknown")
    f.add_argument("--account")
    f.add_argument("--note")
    f.add_argument("--model", help="payload author attribution (e.g. the payload model)")
    f.add_argument("--workflow")
    f = actions.add_parser("canary")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f.add_argument("--field", required=True)
    f.add_argument("--method", default="")
    f.add_argument("--location", choices=LOCATIONS, default="unknown")
    f.add_argument("--account")
    f.add_argument("--workflow")
    f = actions.add_parser("trace")
    f.add_argument("campaign")
    f.add_argument("--marker", required=True)
    f = actions.add_parser("matrix")
    f.add_argument("campaign")
    f.add_argument("--module", required=True)
    f = actions.add_parser("na", help="record an n-a trigger cell with a reason")
    f.add_argument("campaign")
    f.add_argument("--module", required=True)
    f.add_argument("--trigger", choices=TRIGGERS, required=True)
    f.add_argument("--reason", required=True)
    f = actions.add_parser("claim", help="parameter coverage claim; 'full' requires a complete matrix")
    f.add_argument("campaign")
    f.add_argument("--module", required=True)
    f.add_argument("--state", dest="claim_state", choices=CLAIMS, required=True)
    f = actions.add_parser("fingerprint")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f.add_argument("--kind", choices=FINGERPRINT_KINDS, required=True)
    f.add_argument("--value", required=True)
    f.add_argument("--note")
    f = actions.add_parser("packet", help="payload context packet; refuses incomplete context")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f.add_argument("--field", required=True)
    f.add_argument("--case", choices=_case_ids, required=True)
    f = actions.add_parser("payload", help="record payload authorship for a packet file")
    f.add_argument("campaign")
    f.add_argument("--file", required=True, help="context packet JSON file")
    f.add_argument("--model", required=True)
    f.add_argument("--provider")
    f.add_argument("--note")
    f = actions.add_parser("blind", help="validate a blind-XSS surface bundle (callbacks.py rules)")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f.add_argument("--bundle", required=True, help="bundle JSON file; see hunt-xss references")
    s.set_defaults(fn=cmd_fields)
    s = sub.add_parser("waf", help="per-host WAF/filter profiles: observe, plan probes, "
                                   "record outcomes; sends no traffic")
    actions = s.add_subparsers(dest="action", required=True)
    from .waf import LOCATIONS, OUTCOMES
    f = actions.add_parser("plan", help="emit the bounded single-then-pair probe sequence")
    f.add_argument("campaign")
    f.add_argument("--host", required=True)
    f = actions.add_parser("observe", help="classify one probe response against a baseline")
    f.add_argument("campaign")
    f.add_argument("--host", required=True)
    f.add_argument("--element", required=True)
    f.add_argument("--marker", required=True)
    f.add_argument("--baseline-status", type=int)
    f.add_argument("--probe-status", type=int)
    f.add_argument("--baseline-body", help="file with the passing response body")
    f.add_argument("--probe-body", help="file with the probe response body")
    f.add_argument("--baseline-headers", help="JSON object of the baseline headers")
    f.add_argument("--probe-headers", help="JSON object of the probe headers")
    f.add_argument("--reset", action="store_true", help="connection reset / dropped")
    f = actions.add_parser("record", help="store one element outcome per location/content-type")
    f.add_argument("campaign")
    f.add_argument("--host", required=True)
    f.add_argument("--element", required=True)
    f.add_argument("--outcome", choices=OUTCOMES, required=True)
    f.add_argument("--kind", default="char")
    f.add_argument("--paired-with", default="")
    f.add_argument("--location", choices=LOCATIONS, default="query")
    f.add_argument("--content-type", default="text/html")
    f.add_argument("--marker", default="")
    f.add_argument("--note")
    f = actions.add_parser("show")
    f.add_argument("campaign")
    f.add_argument("--host", required=True)
    s.set_defaults(fn=cmd_waf)
    s = sub.add_parser("csrf", help="CSRF action x context x case ledger: inventory, plan, "
                                    "record and status; sends no traffic")
    actions = s.add_subparsers(dest="action", required=True)
    from .csrf import (ARTIFACT_ROLES, ATTEMPT_KINDS, CASES, DELIVERIES, INITIATORS,
                       PREFLIGHT, STATES as CSRF_STATES)
    f = actions.add_parser("sync", help="reconcile actions/contexts from captures, forms, JS and specs")
    f.add_argument("campaign")
    f = actions.add_parser("plan", help="per-action contexts with case readiness and open variants")
    f.add_argument("campaign")
    f.add_argument("--action", dest="action_id", type=int, help="one action ID")
    f.add_argument("--host", help="origin (https://host[:port]) or host name filter")
    f.add_argument("--limit", type=int, default=25)
    f = actions.add_parser("record", help="append one case/variant event with hash-bound artifacts")
    f.add_argument("campaign")
    f.add_argument("--context", type=int, required=True, help="context ID from `csrf plan`")
    f.add_argument("--case", choices=[c["id"] for c in CASES], required=True)
    f.add_argument("--state", choices=CSRF_STATES, required=True)
    f.add_argument("--variant", help="variant ID of the case (see `csrf plan`)")
    f.add_argument("--attempt-kind", choices=ATTEMPT_KINDS, default="browser")
    f.add_argument("--initiator", choices=INITIATORS, default="none",
                   help="initiator relationship to the target origin")
    f.add_argument("--initiator-origin", help="scheme://host[:port] of the initiating page, or null")
    f.add_argument("--delivery", choices=DELIVERIES)
    f.add_argument("--preflight", choices=PREFLIGHT)
    f.add_argument("--browser", help="engine/build label, e.g. 'Chrome 131 stable'")
    f.add_argument("--prerequisite", help="how a same-site initiator origin is controlled, "
                                          "or another prerequisite reference")
    f.add_argument("--artifact", action="append",
                   help=f"ROLE=PATH, campaign-relative; roles: {', '.join(ARTIFACT_ROLES)}")
    f.add_argument("--tool-ref", action="append", help="external reference, e.g. burp-history:1234")
    f.add_argument("--requests", type=int, default=0)
    f.add_argument("--connections", type=int, default=0)
    f.add_argument("--messages", type=int, default=0)
    f.add_argument("--note")
    f = actions.add_parser("status", help="per-origin summary, open cases, stale and gap lists")
    f.add_argument("campaign")
    f.add_argument("--host")
    f = actions.add_parser("verify", help="re-hash every recorded artifact")
    f.add_argument("campaign")
    s.set_defaults(fn=cmd_csrf)
    s = sub.add_parser("import-burp", help="offline Burp XML/JSON export or raw request import; "
                                           "header/cookie names only, values never stored")
    s.add_argument("campaign")
    s.add_argument("file")
    s.add_argument("--account")
    s.add_argument("--role")
    s.add_argument("--tenant")
    s.add_argument("--workflow-state")
    s.add_argument("--scheme", choices=("http", "https"), default="http",
                   help="origin scheme for raw requests (Host header supplies the host)")
    s.set_defaults(fn=cmd_import_burp)
    s = sub.add_parser("import-openapi", help="offline OpenAPI 3 / Swagger 2 import; no fetch")
    s.add_argument("campaign")
    s.add_argument("spec")
    s.set_defaults(fn=cmd_import_openapi)
    s = sub.add_parser("send", help="send one request through the scoped client and store it as evidence")
    s.add_argument("campaign")
    s.add_argument("url")
    s.add_argument("--method", default="GET", help="must be granted by policy.allowed_methods")
    s.add_argument("--header", action="append", help="'Name: value'; repeatable (Host/proxy overrides refused)")
    s.add_argument("--data", help="raw request body (UTF-8)")
    s.add_argument("--data-file", help="request body read from a file")
    s.add_argument("--json", help="JSON request body; sets Content-Type: application/json")
    s.add_argument("--form", action="append", help="key=value form field; repeatable; urlencoded")
    s.add_argument("--content-type", help="override the request Content-Type")
    s.add_argument("--purpose", default="manual-test", help="label stored with the request")
    s.add_argument("--no-follow", action="store_true", help="GET/HEAD: return a 3xx instead of following it")
    s.add_argument("--show-body", type=int, default=2000, help="response bytes to print (0..100000)")
    s.set_defaults(fn=cmd_send)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (ConfigError, ValueError, KeyError, OSError, PolicyViolation, OutOfScope) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
