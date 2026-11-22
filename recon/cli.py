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
  engagement init|status|categorise|debt|block-host|acknowledge-scope <campaign> --id ID
                                               private offline checkpoint and debt reconciliation
  push context|validate <campaign> --engagement ID [--manifest F] [--apply]
                                               offline hunt-push review; no executor or traffic grant
  operator ask|answer|withdraw|list|resume-input|status <campaign> --id ID ...
                                               human queue for captcha/otp/2fa/lockout/environment
                                               blocks; pauses only the asking intent, grants nothing
  intent add|list|show|claim|renew|finish|fail|pause|resume|sweep|context|resume-input|status
         <campaign> --id ID ...                one class x one surface push per intent, leased to
                                               one worker; expired leases sweep back to open and
                                               `exhausted` is a cut-off direction, not coverage
  responses <campaign> [--limit N]        list stored HTTP response IDs (offline)
  fact check|verify|list <campaign> ...    deterministic response-backed predicates
  cloud import|generate|sync|plan|show|record|status|verify <campaign> ...
                                              offline cloud leads, scoped hostname proposals
                                              and operator receipts; no provider executor
  ssrf plan|record|status|correlate <campaign> --asset-id ID ...   offline workflow/evidence
  fields sync|show|record|canary|trace|matrix|na|claim|constraint|constraints|
         surface-expect|surface-review|surfaces|fingerprint|packet|payload|blind <campaign>
                                              field ledger, canary map, trigger-matrix gate,
                                              context packets and blind-XSS correlation
  waf plan|observe|record|show <campaign>     per-host WAF/filter profiles (offline)
  import-burp <campaign> <file> [--account A] Burp XML/JSON export or one raw request (offline)
  import-openapi <campaign> <spec.json>       OpenAPI 3 / Swagger 2 declared fields (offline)
  chain status|add|realism <campaign> [--file F]  cross-class todolist/lineage + realism gate
  csrf sync|plan|record|status|verify <campaign>  CSRF action x context x case ledger (offline)
  ssti probes|surface|trace|fingerprint|plan|record|status|verify <campaign>  offline SSTI evidence
  cache record|show|status|verify <campaign>     offline cache poisoning/deception evidence ledger
  cache import|profile|isolation|reviews|review|verify-reviews <campaign>  offline capture review
  http-review inspect|show|status|verify <campaign>  local HTTP/1 framing lint; no sender
  rce declare|record|show|status|verify <campaign>  offline sink and owned-lab proof review
  authz sync|plan|record|status|verify <campaign>  offline access-control/MA workflow
  authpolicy sync|declare|plan|record|derive|status|verify <campaign>
                                               offline auth-policy exact-operation review
   upload sync|declare|plan|fixture|record|callback|cleanup|resume|status|verify <campaign>
                                              offline file-upload lifecycle ledger; inert fixtures only
   logic sync|declare|probe|observe|close|plan|record|cleanup|resume|status|verify <campaign>
   race sync|declare|profile|plan|attest|record|status|verify <campaign>
                                              offline invariant/race evidence; no gate sender
  send <campaign> <url> [--method M] [--header 'K: V'] [--json J | --form k=v | --data D]
                                             one request through the scoped client; prints request_id
  exec <campaign> --tool T --engagement ID --estimate N [--plan] -- <tool args>
                                             one allowlisted external tool (httpx, katana, ffuf,
                                             nuclei, dalfox, sqlmap) under the same scope, method,
                                             pacing and campaign budget as `send`; the estimate is
                                             pre-charged and never refunded

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
    from . import skillguard
    # Preflight: the skills a model will read are not the engine's gates, but a skill
    # that has lost its scope-and-limits language is worth knowing about before a run
    # rather than after. Reports by default; refuses only with --require-intact-skills.
    guard = skillguard.verify(strict=bool(getattr(a, "require_intact_skills", False)))
    if guard["state"] != "intact":
        print(skillguard.report_text(guard))
    if guard["blocking"]:
        print("refusing to run: a skill lost a guardrail marker and "
              "--require-intact-skills was given", file=sys.stderr)
        return 1
    ctx = _load(a.campaign)
    if a.rerun:
        print(f"re-queued {ctx.store.rerun(a.rerun)} {a.rerun} job(s)")
    stats = ctx.run(max_jobs=a.max_jobs)
    print(f"run: {stats}")
    for p in write_reports(ctx):
        print(f"wrote {p}")
    return 0


def cmd_skills_record(a) -> int:
    from . import skillguard
    data = skillguard.record(note=a.note)
    print(f"recorded {len(data['skills'])} skills to "
          f"{skillguard.MANIFEST.relative_to(skillguard.REPO)}")
    print("digests and guardrail-marker counts only; engine gates do not consult this file")
    return 0


def cmd_skills_verify(a) -> int:
    from . import skillguard
    result = skillguard.verify(strict=a.strict)
    print(skillguard.report_text(result))
    return 1 if result["blocking"] else 0


def cmd_har(a) -> int:
    from .har import import_har
    from .report import write_reports
    ctx = _load(a.campaign)
    try:
        stats = import_har(ctx, Path(a.har), a.account, a.role, a.tenant, a.workflow_state,
                           a.script_bodies)
        print(f"import: {stats}")
        print("HAR script/map URLs are inventory only; --script-bodies parses captured bodies "
              "offline with `recon js sync` (no unauthenticated refetch)")
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
    if a.bug_class == "js-bundle" and a.status in ("tested", "confirmed", "refuted", "n-a"):
        from .jsledger import JsLedger
        state = JsLedger(ctx).status(origin=ctx.store.get_asset(a.asset_id)["value"])
        if not state["complete"]:
            raise ValueError("JS inventory has open stages/leads; a coarse cov row cannot close it")
    ctx.store.set_coverage(a.asset_id, a.bug_class, a.status, a.note)
    write_reports(ctx)
    print(f"coverage[{a.asset_id}, {a.bug_class}] = {a.status}")
    return 0


def cmd_status(a) -> int:
    ctx = _load(a.campaign)
    jobs = ctx.store.jobs()
    print(f"mode={ctx.policy.mode} requests_sent={ctx.store.request_count()}")
    print(f"campaign_http_attempts={ctx.store.network_attempts()}/{ctx.policy.max_campaign_requests}")
    from .pipeline import JOB_NEEDS
    print(f"llm_agents=0 scheduler=1 handlers={len(JOB_NEEDS)} imports={len(ctx.store.imports())} "
          f"endpoint_operations={len(ctx.store.operations())}")
    for (kind, state), n in sorted(Counter((j["kind"], j["state"]) for j in jobs).items()):
        print(f"  {kind:10} {state:8} {n}")
    return 0


def cmd_js(a) -> int:
    from .jsledger import JsLedger
    ctx = _load(a.campaign)
    try:
        ledger = JsLedger(ctx)
        if a.action == "sync":
            result = ledger.sync(a.origin)
        elif a.action == "verify":
            result = ledger.verify()
        elif a.action == "builds":
            result = ledger.builds(a.origin)
        elif a.action == "plan":
            result = ledger.plan(a.family or "", a.lane, a.top, a.packets, a.origin)
        elif a.action == "show":
            result = ledger.show(a.lead)
        elif a.action == "diff":
            result = ledger.diff(a.origin, a.from_build or "", a.to_build or "")
        elif a.action == "record":
            result = ledger.record(a.lead, state=a.state or "", ref=a.ref or "",
                                   reason=a.reason or "", rung=a.rung or "",
                                   outcome=a.outcome or "", response_id=a.response)
        elif a.action == "pair":
            result = ledger.asset_pair(a.low_response, a.owner_response)
        elif a.action == "resume":
            result = ledger.resume_retained(a.origin, a.reason)
        elif a.action == "export":
            result = ledger.export(a.kind, Path(a.out))
        else:
            result = ledger.status(a.limit, a.origin)
        print(json.dumps(result, indent=2))
        return 2 if a.action == "verify" and not result["ok"] else 0
    finally:
        ctx.store.close()


def cmd_catalog(a) -> int:
    from .catalog import catalog, render_catalog
    data = catalog()
    print(json.dumps(data, indent=2) if a.json else render_catalog(data))
    return 0


def cmd_takeover(a) -> int:
    from .takeover import TakeoverLedger, read_json
    ctx = _load(a.campaign)
    try:
        ledger = TakeoverLedger(ctx)
        if a.action == "import":
            result = ledger.import_capture(read_json(a.file))
        elif a.action == "sync":
            result = ledger.sync()
        elif a.action == "show":
            result = ledger.show(a.candidate)
        elif a.action in ("record", "cleanup"):
            result = getattr(ledger, a.action)(read_json(a.file))
        elif a.action == "verify":
            result = ledger.verify()
        else:
            result = getattr(ledger, a.action)(a.limit)
        print(json.dumps(result, indent=2))
        return 2 if a.action == "verify" and not result["ok"] else 0
    finally:
        ctx.store.close()


def cmd_cloud(a) -> int:
    """Cloud candidates and operator evidence; no target or provider execution."""
    from .cloud import CloudLedger
    ctx = _load(a.campaign)
    try:
        ledger = CloudLedger(ctx)
        if a.action == "import":
            result = ledger.import_text(a.file, a.media_type, a.historical)
        elif a.action == "generate":
            result = ledger.generate_file(a.file)
        elif a.action == "sync":
            result = ledger.sync(a.limit, a.offset)
        elif a.action == "plan":
            result = ledger.plan(a.limit)
        elif a.action == "show":
            result = ledger.show(a.reference)
        elif a.action == "record":
            result = ledger.record_file(a.file)
        elif a.action == "verify":
            result = ledger.verify()
        else:
            result = ledger.status(a.limit)
        print(json.dumps(result, indent=2))
        return 2 if a.action == "verify" and not result["ok"] else 0
    finally:
        ctx.store.close()


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
            lineage = a.lineage or ""
            if lineage:
                from .jsledger import JsLedger
                JsLedger(ctx)  # also creates module-owned tables in older campaigns
                if not lineage.startswith("js:") or not ctx.store.db.execute(
                        "SELECT 1 FROM js_leads WHERE lead_key=?", (lineage,)).fetchone():
                    raise ValueError("--lineage needs a known js:<lead-key>; no inferred chain")
            fid, created = fx.add(a.title, a.bug_class, asset_id=a.asset, url=a.url,
                                   severity=a.severity, tech=a.tech or [], note=a.note,
                                   detail={"lineage": [lineage]} if lineage else None)
            print(f"{'created' if created else 'exists'} finding #{fid} [lead]")
        elif a.action == "move":
            measured = None
            if a.data_impact:
                measured = json.loads(Path(a.data_impact).read_text(encoding="utf-8"))
            f = fx.move(a.id, a.stage, note=a.note, severity=a.severity,
                        replay=Path(a.replay) if a.replay else None,
                        control=Path(a.control) if a.control else None,
                        impact=Path(a.impact) if a.impact else None,
                        report=Path(a.report) if a.report else None,
                        poe_level=a.poe_level, measurement=a.measurement,
                        quote=a.quote, data_impact=measured, override=a.override,
                        impact_kind=a.impact_kind)
            print(f"finding #{f['id']} -> {f['stage']} (PoE {f['poe_level']}"
                  f"{', ' + f['severity'] if f['severity'] else ''})")
            if measured is not None:
                from .dataimpact import summarise, validate
                print(f"data impact: {summarise(validate(measured))}", file=sys.stderr)
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


def cmd_engagement(a) -> int:
    from .engagement import Engagement
    ctx = _load(a.campaign)
    try:
        engagement = Engagement(ctx, a.id)
        if a.action == "init":
            data = engagement.init()
        elif a.action == "status":
            data = engagement.checkpoint()
        elif a.action == "categorise":
            data = engagement.categorise()
        elif a.action == "debt":
            data = engagement.reconcile()
        elif a.action == "acknowledge-scope":
            data = engagement.acknowledge_scope()
        else:
            data = engagement.block_host(a.response, a.reason, a.note or "")
        print(json.dumps(data, indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_push(a) -> int:
    from .engagement import Engagement
    from .push import context, review
    ctx = _load(a.campaign)
    try:
        engagement = Engagement(ctx, a.engagement)
        if a.action == "context":
            result = context(ctx, engagement)
        else:
            result = review(ctx, Path(a.manifest), engagement, apply=a.apply)
        print(json.dumps(result, indent=2))
        return 0
    finally:
        ctx.store.close()


def cmd_operator(a) -> int:
    from .operator import OperatorQueue
    ctx = _load(a.campaign)
    try:
        queue = OperatorQueue(ctx, a.id)
        if a.action == "ask":
            data = queue.ask(a.intent, a.question, a.reason, a.screenshot or "")
        elif a.action == "answer":
            data = queue.answer(a.ref, a.text)
        elif a.action == "withdraw":
            data = queue.withdraw(a.ref, a.note or "")
        elif a.action == "list":
            data = {"entries": queue.entries(a.state or "")}
        elif a.action == "resume-input":
            data = {"intent": a.intent, "input": queue.resume_input(a.intent)}
        else:
            data = queue.status()
        print(json.dumps(data, indent=2))
        # A pending question is a blocked intent, not a failed command: exit 0 so a
        # scheduler reads the JSON and skips that one intent. `resume-input` returns 2
        # when there is no answered reply to resume with, so a caller cannot mistake
        # an empty string for an answer.
        if a.action == "resume-input" and not data["input"]:
            return 2
        return 0
    finally:
        ctx.store.close()


def cmd_intent(a) -> int:
    """The intent queue: one class x one surface push, leased to one worker.

    Exit codes: 0 normal, 2 "nothing to do" — `claim` found no claimable intent, or
    `resume-input` has nothing to continue with — so a scheduler can tell the
    difference between an empty queue and a failure.
    """
    from .intents import IntentQueue
    ctx = _load(a.campaign)
    try:
        queue = IntentQueue(ctx, a.id)
        empty = False
        if a.action == "add":
            data = queue.add(a.summary, getattr(a, "class"), surface_ids=a.surface,
                             parent_ids=a.parent, skill=a.skill or "")
        elif a.action == "list":
            data = {"intents": queue.intents(a.state or "")}
        elif a.action == "show":
            data = queue.get(a.intent)
        elif a.action == "claim":
            data = queue.claim(a.worker, ident=a.intent or 0)
            empty = data is None
            data = data or {"claimed": None, "note": "no claimable intent: all are "
                                                     "running, waiting on a human, in "
                                                     "backoff or finished"}
        elif a.action == "renew":
            data = queue.renew(a.intent, a.token)
        elif a.action == "finish":
            data = queue.finish(a.intent, a.token, a.state, a.note or "")
        elif a.action == "fail":
            data = queue.fail(a.intent, a.token, a.note or "")
        elif a.action == "pause":
            data = queue.pause(a.intent, a.note or "")
        elif a.action == "resume":
            data = queue.resume(a.intent, a.note or "")
        elif a.action == "sweep":
            data = queue.sweep()
        elif a.action == "context":
            data = queue.context(a.intent)
        elif a.action == "resume-input":
            data = {"intent": a.intent, "input": queue.resume_input(a.intent)}
            empty = not data["input"]
        else:
            data = queue.status()
        print(json.dumps(data, indent=2))
        return 2 if empty else 0
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
        elif a.action == "diff":
            result = ledger.diff(a.module)
        elif a.action == "constraint":
            result = ledger.constraint(a.asset_id, a.method, a.location, a.field,
                                       a.kind, a.value, a.source, a.source_ref, a.response)
        elif a.action == "constraints":
            result = ledger.constraints(a.asset_id)
        elif a.action == "surface-expect":
            result = ledger.expect_surface(a.asset_id, a.field, a.surface, a.case,
                                           a.source_ref, a.reason, a.account, a.workflow)
        elif a.action == "surface-review":
            result = ledger.review_surface(a.expectation, a.state, a.note, a.response)
        elif a.action == "surfaces":
            result = ledger.surface_matrix(a.module)
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


def cmd_authz(a) -> int:
    from .authz import AuthzLedger
    ctx = _load(a.campaign)
    try:
        ledger = AuthzLedger(ctx)
        if a.action == "sync":
            result = ledger.sync()
        elif a.action == "plan":
            result = ledger.plan(a.target, a.limit)
        elif a.action == "record":
            result = ledger.record(a.context, a.case, a.state, variant=a.variant,
                                   grant=a.grant, parent_id=a.parent, impact=a.impact,
                                   marker=a.marker, proof_basis=a.proof_basis,
                                   artifacts=a.artifact, tool_refs=a.tool_ref,
                                   requests=a.requests, owner=a.owner, root_key=a.root_key,
                                   related_cases=a.related_case, note=a.note)
        elif a.action == "verify":
            result = ledger.verify()
        else:
            result = ledger.status(a.limit)
        print(json.dumps(result, indent=2))
        return 0 if result.get("verified", result.get("integrity", {}).get("verified", True)) else 2
    finally:
        ctx.store.close()


def cmd_authpolicy(a) -> int:
    from .authpolicy import AuthPolicyLedger
    ctx = _load(a.campaign)
    try:
        ledger = AuthPolicyLedger(ctx)
        if a.action == "sync":
            result = ledger.sync()
        elif a.action == "declare":
            result = ledger.declare(a.asset_id, a.url, a.method, a.entry_point,
                                    a.source_ref, a.account, a.role, a.tenant,
                                    a.workflow, a.representation)
        elif a.action == "plan":
            result = ledger.plan(a.operation, a.limit, a.offset)
        elif a.action == "record":
            refs = {}
            for item in a.ref or []:
                if ":" not in item:
                    raise ValueError("--ref must be ROLE:stored-response-ID")
                role, ident = item.rsplit(":", 1)
                if role in refs or not ident.isdecimal():
                    raise ValueError("--ref roles must be unique and IDs positive integers")
                refs[role] = int(ident)
            result = ledger.record(a.operation, a.case, a.state, refs, a.note, a.source)
        elif a.action == "derive":
            result = ledger.derive(a.file)
        elif a.action == "verify":
            result = ledger.verify(a.limit, a.offset)
        else:
            result = ledger.status(a.limit, a.offset)
        print(json.dumps(result, indent=2))
        return 0 if result.get("verified", True) else 2
    finally:
        ctx.store.close()


def cmd_invariant_view(a) -> int:
    from .logic import LogicLedger
    from .race import RaceLedger
    from .invariants import read_json_file
    ctx = _load(a.campaign)
    try:
        ledger = LogicLedger(ctx) if a.cmd == "logic" else RaceLedger(ctx)
        if a.action == "sync":
            result = ledger.sync()
        elif a.action == "declare":
            result = ledger.declare(read_json_file(a.file))
        elif a.action in ("record", "observe", "attest"):
            result = getattr(ledger, a.action)(read_json_file(a.file))
        elif a.action == "probe":
            result = ledger.probe(a.workflow, a.limit)
        elif a.action == "plan":
            result = ledger.plan(**({"workflow": a.workflow, "limit": a.limit} if a.cmd == "logic" else
                                    {"context": a.context, "case": a.case, "limit": a.limit}))
        elif a.action == "profile":
            result = ledger.profile(a.host)
        elif a.action == "close":
            result = ledger.close(a.observation, a.reason, a.event)
        elif a.action == "cleanup":
            result = ledger.model.cleanup(a.event, a.outcome, a.artifact, a.note)
        elif a.action == "resume":
            result = ledger.model.resume(a.host, a.note)
        elif a.action == "verify":
            result = ledger.verify()
        else:
            result = ledger.status(a.limit)
        print(json.dumps(result, indent=2, default=str))
        return 2 if a.action == "verify" and not result["verified"] else 0
    finally:
        ctx.store.close()


def cmd_upload(a) -> int:
    from .upload import UploadLedger
    ctx = _load(a.campaign)
    try:
        ledger = UploadLedger(ctx)
        if a.action == "sync":
            result = ledger.sync()
        elif a.action == "declare":
            result = ledger.declare(a.url, a.method, a.field, a.transport, a.surface, a.note)
        elif a.action == "plan":
            result = ledger.plan(a.sink, a.limit)
        elif a.action == "fixture":
            result = ledger.fixture(a.kind, a.size)
        elif a.action == "record":
            result = ledger.record(
                a.context, a.case, a.state, channel=a.channel, grant=a.grant, marker=a.marker,
                control_marker=a.control_marker, facts=a.fact or [], artifacts=a.artifact or [],
                layer=a.layer, request_ref=a.request_ref, response_status=a.response_status,
                route=a.route, stop_trigger=a.stop_trigger,
                served_headers=json.loads(a.served_headers) if a.served_headers else None,
                requests=a.requests, bytes_sent=a.bytes, objects=a.objects,
                object_ref=a.object_ref, tool_refs=a.tool_ref or [], root_key=a.root_key,
                note=a.note)
        elif a.action == "callback":
            result = ledger.callback(a.event, a.kind, a.url, sent_at=a.sent_at,
                                     observed_at=a.observed_at, deadline=a.deadline,
                                     control_marker=a.control_marker, health=a.health,
                                     job_id=a.job_id, artifacts=a.artifact or [], note=a.note)
        elif a.action == "cleanup":
            result = ledger.cleanup(a.event, a.outcome, a.artifact, a.note)
        elif a.action == "resume":
            result = ledger.resume(a.host, a.note)
        elif a.action == "verify":
            result = ledger.verify()
        else:
            result = ledger.status(a.limit)
        print(json.dumps(result, indent=2))
        return 0 if result.get("verified", result.get("integrity", {}).get("verified", True)) else 2
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


def cmd_ssti(a) -> int:
    from .ssti import SstiLedger
    ctx = _load(a.campaign)
    try:
        ledger = SstiLedger(ctx)
        if a.action == "probes":
            if a.set_id is None and (a.asset_id is None or a.field is None):
                raise ValueError("probes requires --set or --asset-id and --field")
            result = (ledger.probes(a.set_id) if a.set_id is not None else
                      ledger.start(a.asset_id, a.field, a.method, a.location, a.account, a.compact,
                                   a.role, a.tenant, a.workflow))
        elif a.action == "surface":
            result = ledger.add_surface(a.set_id, a.kind, a.label)
        elif a.action == "trace":
            result = ledger.trace(a.surface_id, a.probe, response_id=a.response,
                                  artifact=a.artifact)
        elif a.action == "record":
            result = ledger.record(a.surface_id, a.case, a.state, a.note, a.severity,
                                   grant=a.grant, target=a.target, exercise=a.exercise,
                                   attempts=a.attempts, artifacts=a.artifact)
        elif a.action == "fingerprint":
            result = ledger.fingerprint(a.set_id)
        elif a.action == "plan":
            result = ledger.plan(a.set_id)
        elif a.action == "status":
            result = ledger.status(a.set_id)
        else:
            result = ledger.verify()
        print(json.dumps(result, indent=2))
        return 0 if result.get("verified", result.get("integrity", {}).get("verified", True)) else 2
    finally:
        ctx.store.close()


def cmd_cache(a) -> int:
    from .cache import CacheLedger
    from .cache_review import CacheReview
    ctx = _load(a.campaign)
    try:
        ledger, review = CacheLedger(ctx), CacheReview(ctx)
        if a.action == "import":
            result = review.import_file(a.file, a.format, account=a.account, role=a.role,
                                        tenant=a.tenant, workflow=a.workflow)
        elif a.action in ("profile", "isolation"):
            result = getattr(review, a.action)(a.file)
        elif a.action == "review":
            result = review.show(a.id)
        elif a.action == "reviews":
            result = review.status(a.kind, a.limit, a.offset)
        elif a.action == "verify-reviews":
            result = review.verify(a.limit, a.offset)
        elif a.action == "record":
            result = ledger.record_file(a.file)
        elif a.action == "show":
            result = ledger.show(a.reference)
        elif a.action == "status":
            result = ledger.status(a.limit)
        else:
            result = ledger.verify()
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok", True) else 2
    finally:
        ctx.store.close()


def cmd_http_review(a) -> int:
    from .http_review import HttpReview
    ctx = _load(a.campaign)
    try:
        review = HttpReview(ctx)
        if a.action == "inspect":
            result = review.inspect(a.file, a.url, a.kind)
        elif a.action == "show":
            result = review.show(a.id)
        else:
            result = getattr(review, a.action)(a.limit, a.offset)
        print(json.dumps(result, indent=2))
        # Capture lint rejection is a recorded observation, not a failed import.
        return 0 if result.get("ok", True) else 2
    finally:
        ctx.store.close()


def cmd_rce(a) -> int:
    from .rce import RceLedger
    ctx = _load(a.campaign)
    try:
        ledger = RceLedger(ctx)
        if a.action == "declare":
            result = ledger.declare(a.file)
        elif a.action == "record":
            result = ledger.record(a.file)
        elif a.action == "show":
            result = ledger.show(a.id)
        else:
            result = getattr(ledger, a.action)(a.limit, a.offset)
        print(json.dumps(result, indent=2))
        return 0 if result.get("ok", True) else 2
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


def cmd_exec(a) -> int:
    """One allowlisted external tool under recon's scope, methods, pacing and budget.

    Exit codes: 0 launched and the tool exited cleanly (or --plan validated), 1 refused
    before anything was launched, 2 launched but the tool failed or hit its time cap.
    """
    from .engagement import Engagement
    from .toolexec import execute, prepare
    ctx = _load(a.campaign)
    try:
        argv = list(a.args or [])
        if argv and argv[0] == "--":
            argv = argv[1:]
        blocked = Engagement(ctx, a.engagement).blocked_hosts()
        plan = prepare(ctx, a.tool, argv, a.estimate, blocked=blocked)
        if a.plan:
            print(json.dumps(plan, indent=2))
            return 0
        record = execute(ctx, plan, engagement=a.engagement, import_output=not a.no_import)
        print(json.dumps(record, indent=2))
        return 0 if record.get("exit_code") == 0 else 2
    finally:
        ctx.store.close()


def cmd_send(a) -> int:
    """One request through ScopedClient: scope, method grant, rate, budgets, pinned egress."""
    import hashlib
    from .net import FetchError
    from .untrusted import frame
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
        # The response body is the target's text and this output goes straight into a
        # model's context, so the preview is handed over nonce-framed as data.
        preview = resp.body[:a.show_body].decode("utf-8", "replace")
        print(json.dumps({
            "request_id": resp.request_id, "method": method, "url": resp.url, "status": resp.status,
            "redirect_chain": resp.redirect_chain, "blocked_redirect": resp.blocked_redirect,
            "headers": resp.headers, "body_bytes": len(resp.body),
            "body_sha256": hashlib.sha256(resp.body).hexdigest(), "truncated": resp.truncated,
            "body_preview": frame(preview, "target-response", label=resp.url) if preview else ""},
            indent=2))
        print(f"evidence: python3 -m recon fact check {a.campaign} --response {resp.request_id} "
              "--predicate '<JSON>'", file=sys.stderr)
        return 0
    except FetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        ctx.store.close()


def main(argv=None) -> int:
    from .intents import STATES
    from .operator import REASONS
    from .toolexec import PROFILES
    p = argparse.ArgumentParser(prog="python3 -m recon", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("cloud", help="offline cloud references/triage/evidence; no provider traffic")
    actions = s.add_subparsers(dest="action", required=True)
    for action in ("import", "generate", "sync", "plan", "show", "record", "status", "verify"):
        command = actions.add_parser(action)
        command.add_argument("campaign")
        if action in ("import", "generate", "record"):
            command.add_argument("--file", required=True, help="campaign-relative artifact path")
        if action == "import":
            command.add_argument("--media-type", default="text/plain")
            command.add_argument("--historical", action="store_true")
        if action == "show":
            command.add_argument("--reference", type=int, required=True)
        if action in ("sync", "plan", "status"):
            command.add_argument("--limit", type=int, default=25 if action != "sync" else 200)
        if action == "sync":
            command.add_argument("--offset", type=int, default=0, help="next_offset from prior sync page")
        command.set_defaults(fn=cmd_cloud)
    s = sub.add_parser("takeover", help="offline DNS/host/trust/claim evidence; never claims resources")
    actions = s.add_subparsers(dest="action", required=True)
    for action in ("import", "sync", "plan", "show", "record", "cleanup", "status", "verify"):
        command = actions.add_parser(action)
        command.add_argument("campaign")
        if action == "import":
            command.add_argument("file", help="normalized schema-1 DNS capture")
        if action in ("record", "cleanup"):
            command.add_argument("--file", required=True)
        if action == "show":
            command.add_argument("--candidate", type=int, required=True)
        if action in ("plan", "status"):
            command.add_argument("--limit", type=int, default=25)
        command.set_defaults(fn=cmd_takeover)
    for view, actions_list in (("logic", ("sync", "declare", "probe", "observe", "close", "plan",
                                         "record", "cleanup", "resume", "status", "verify")),
                               ("race", ("sync", "declare", "profile", "plan", "attest",
                                         "record", "status", "verify"))):
        ledger_parser = sub.add_parser(view, help="offline workflow invariant evidence (no target sends)")
        ledger_actions = ledger_parser.add_subparsers(dest="action", required=True)
        for action in actions_list:
            command = ledger_actions.add_parser(action)
            command.add_argument("campaign")
            if action in ("declare", "observe", "attest", "record"):
                command.add_argument("--file", required=True, help="bounded campaign evidence JSON")
            if action == "probe":
                command.add_argument("--workflow", required=True)
            if action == "plan" and view == "logic":
                command.add_argument("--workflow")
            if action == "plan" and view == "race":
                command.add_argument("--context", type=int)
                command.add_argument("--case")
            if action in ("plan", "probe", "status"):
                command.add_argument("--limit", type=int, default=25)
            if action == "profile" or action == "resume":
                command.add_argument("--host", required=True)
            if action == "close":
                command.add_argument("--observation", required=True, type=int)
                command.add_argument("--reason", required=True)
                command.add_argument("--event", type=int)
            if action == "cleanup":
                command.add_argument("--event", required=True, type=int)
                command.add_argument("--outcome", required=True)
                command.add_argument("--artifact", default="")
                command.add_argument("--note", default="")
            if action == "resume":
                command.add_argument("--note", required=True)
            command.set_defaults(fn=cmd_invariant_view)
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
    s.add_argument("--require-intact-skills", action="store_true",
                   help="refuse the run when a skill lost a guardrail marker")
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("import-har")
    s.add_argument("campaign")
    s.add_argument("har")
    s.add_argument("--account", required=True, help="canary account label, e.g. alice")
    s.add_argument("--role", default="")
    s.add_argument("--tenant", default="")
    s.add_argument("--workflow-state", default="")
    s.add_argument("--script-bodies", action="store_true",
                   help="opt in to private script/map response bodies only; no request bodies")
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

    s = sub.add_parser("skills", help="skill-file integrity: digest + guardrail-marker "
                                      "baseline; prose is never parsed as policy")
    sk = s.add_subparsers(dest="action", required=True)
    f = sk.add_parser("record", help="record the current skills as the reviewed baseline")
    f.add_argument("--note", default="")
    f.set_defaults(fn=cmd_skills_record)
    f = sk.add_parser("verify", help="report drift from the recorded baseline")
    f.add_argument("--strict", action="store_true",
                   help="exit non-zero when a guardrail marker was lost")
    f.set_defaults(fn=cmd_skills_verify)
    s = sub.add_parser("js", help="offline JS build/asset/lead ledger; no probes or finding promotion")
    js_actions = s.add_subparsers(dest="action", required=True)
    for action in ("sync", "status", "builds", "verify"):
        f = js_actions.add_parser(action)
        f.add_argument("campaign")
        if action != "verify":
            f.add_argument("--origin", help="exact origin; no scope expansion")
        if action == "status":
            f.add_argument("--limit", type=int, default=30)
    f = js_actions.add_parser("plan", help="ranked JS leads and value-free test packets")
    f.add_argument("campaign")
    f.add_argument("--origin")
    f.add_argument("--family")
    f.add_argument("--lane", choices=("current", "stale", "all"), default="all")
    f.add_argument("--top", type=int, default=30)
    f.add_argument("--packets", action="store_true")
    f = js_actions.add_parser("show", help="one lead, sightings, packet, rung receipts")
    f.add_argument("campaign")
    f.add_argument("lead")
    f = js_actions.add_parser("diff", help="compare two explicitly identified builds")
    f.add_argument("campaign")
    f.add_argument("--origin", required=True)
    f.add_argument("--from", dest="from_build")
    f.add_argument("--to", dest="to_build")
    f = js_actions.add_parser("record", help="offline handoff or individual rung observation")
    f.add_argument("campaign")
    f.add_argument("lead")
    f.add_argument("--state")
    f.add_argument("--ref")
    f.add_argument("--reason")
    f.add_argument("--rung")
    f.add_argument("--outcome")
    f.add_argument("--response", type=int, help="stored request ID for a status-backed rung")
    f = js_actions.add_parser("pair", help="paired J17 asset-delivery observation, not a finding")
    f.add_argument("campaign")
    f.add_argument("--low-response", type=int, required=True)
    f.add_argument("--owner-response", type=int, required=True)
    f = js_actions.add_parser("resume", help="record review after a retained-asset 429/5xx stop; no HTTP")
    f.add_argument("campaign")
    f.add_argument("--origin", required=True)
    f.add_argument("--reason", required=True)
    f = js_actions.add_parser("export", help="sanitized offline summary")
    f.add_argument("campaign")
    f.add_argument("--kind", required=True)
    f.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_js)
    s = sub.add_parser("lookup", help="fingerprinted versions -> searchsploit/Sploitus/KEV leads")
    s.add_argument("campaign")
    s.add_argument("--kev-file", help="offline KEV JSON instead of the cached/fetched feed")
    s.add_argument("--no-kev", action="store_true")
    s.add_argument("--no-sploitus", action="store_true")
    s.add_argument("--no-searchsploit", action="store_true")
    s.add_argument("--refresh", action="store_true", help="explicitly retry cached/suppressed intel providers")
    s.set_defaults(fn=cmd_lookup)
    from .findings import IMPACT_KINDS, POE_LEVELS, RELATIONS, SEVERITIES, STAGES
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
    f.add_argument("--lineage", help="known js:<lead-key>; references a lead, never confirms a chain")
    f.add_argument("--note")
    f = fsub.add_parser("move")
    f.add_argument("campaign")
    f.add_argument("id", type=int)
    f.add_argument("stage", choices=STAGES)
    for opt in ("--replay", "--control", "--impact", "--report", "--note"):
        f.add_argument(opt)
    f.add_argument("--severity", choices=SEVERITIES)
    f.add_argument("--poe-level", type=int, choices=POE_LEVELS, dest="poe_level",
                   help="0 nothing · 1 error/timing/variation · 2 structural manipulation · "
                        "3 data extracted or action performed · 4 critical impact demonstrated; "
                        "impact-proven needs 3 or 4")
    f.add_argument("--measurement",
                   help="the impact as a number with a denominator (\"3 of 40 ids returned "
                        "another tenant's rows\"), or \"not measurable: <reason>\"")
    f.add_argument("--quote",
                   help="verbatim string from the impact artifact, headers included, that "
                        "shows the result")
    f.add_argument("--data-impact", dest="data_impact",
                   help="JSON file measuring what the primitive yields: reachable, sampled, "
                        "enumeration, classes, subjects, redacted fingerprints. Required for a "
                        "data-exposure class and for PoE 4 — reach is not impact")
    f.add_argument("--impact-kind", dest="impact_kind", choices=IMPACT_KINDS,
                   help="what the finding demonstrates. Defaults to data-exposure for a "
                        "data class, which then requires --data-impact; declare another "
                        "kind when the impact is an action rather than data")
    f.add_argument("--override",
                   help="reason a severity above the computed ceiling is nonetheless right")
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
    s = sub.add_parser("engagement", help="private offline engagement state, category deltas and debt")
    actions = s.add_subparsers(dest="action", required=True)
    for action in ("init", "status", "categorise", "debt", "block-host", "acknowledge-scope"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--id", required=True, help="private engagement slug")
        if action == "block-host":
            f.add_argument("--response", type=int, required=True, help="stored target response ID")
            f.add_argument("--reason", required=True,
                           choices=("429", "challenge", "lockout", "unexpected-effect", "cleanup"))
            f.add_argument("--note", default="")
    s.set_defaults(fn=cmd_engagement)
    s = sub.add_parser("push", help="offline hunt-push manifest review; no model or sender")
    actions = s.add_subparsers(dest="action", required=True)
    for action in ("context", "validate"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--engagement", required=True, help="existing private engagement slug")
        if action == "validate":
            f.add_argument("--manifest", required=True)
            f.add_argument("--apply", action="store_true", help="record offline review receipt only")
    s.set_defaults(fn=cmd_push)
    s = sub.add_parser("operator", help="offline human queue; pauses only the asking intent "
                                        "and never grants scope, methods or budget")
    actions = s.add_subparsers(dest="action", required=True)
    for action in ("ask", "answer", "withdraw", "list", "resume-input", "status"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--id", required=True, help="private engagement slug")
        if action == "ask":
            f.add_argument("--intent", required=True, help="the blocked intent's ref")
            f.add_argument("--question", required=True,
                           help="exactly what the operator must supply or do; for an "
                                "environment block, the one copy-pastable command")
            f.add_argument("--reason", required=True, choices=REASONS)
            f.add_argument("--screenshot", default="",
                           help="optional image already inside the engagement directory")
        elif action == "answer":
            f.add_argument("--ref", type=int, required=True)
            f.add_argument("--text", required=True, help="the operator's reply; data, not a grant")
        elif action == "withdraw":
            f.add_argument("--ref", type=int, required=True)
            f.add_argument("--note", default="")
        elif action == "list":
            f.add_argument("--state", default="", choices=("", "pending", "answered", "withdrawn"))
        elif action == "resume-input":
            f.add_argument("--intent", required=True)
    s.set_defaults(fn=cmd_operator)

    s = sub.add_parser("intent", help="offline intent queue: one class x one surface push, "
                                       "leased to one worker; scheduling only, never coverage")
    actions = s.add_subparsers(dest="action", required=True)
    for action in ("add", "list", "show", "claim", "renew", "finish", "fail",
                   "pause", "resume", "sweep", "context", "resume-input", "status"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--id", required=True, help="private engagement slug")
        if action == "add":
            f.add_argument("--summary", required=True,
                           help="the target, the action and why it is worth pushing")
            f.add_argument("--class", required=True, dest="class",
                           help="coverage bug class; routes the hunt skill to load")
            f.add_argument("--surface", action="append", default=[],
                           help="surface reference, e.g. ep-118; repeatable")
            f.add_argument("--parent", action="append", default=[],
                           help="fact or finding this follows from; repeatable")
            f.add_argument("--skill", default="",
                           help="override the routed skill; an unrouted class uses `explore`")
        elif action == "list":
            f.add_argument("--state", default="", choices=("",) + STATES)
        elif action == "claim":
            f.add_argument("--worker", required=True, help="worker id taking the lease")
            f.add_argument("--intent", type=int, default=0,
                           help="claim this intent specifically, if it is claimable")
        elif action in ("show", "context", "resume-input"):
            f.add_argument("--intent", type=int, required=True)
        elif action in ("renew", "finish", "fail"):
            f.add_argument("--intent", type=int, required=True)
            f.add_argument("--token", required=True, help="the lease token from `claim`")
            f.add_argument("--note", default="")
            if action == "finish":
                f.add_argument("--state", required=True, choices=("done", "exhausted", "stopped"),
                               help="`exhausted` is a cut-off direction, not coverage")
        elif action in ("pause", "resume"):
            f.add_argument("--intent", type=int, required=True)
            f.add_argument("--note", default="")
    s.set_defaults(fn=cmd_intent)

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
    f = actions.add_parser("diff", help="value-free, context-safe sent versus declared names")
    f.add_argument("campaign")
    f.add_argument("--module", required=True)
    from .fields import CONSTRAINT_KINDS, CONSTRAINT_SOURCES, SURFACE_CASES
    f = actions.add_parser("constraint", help="declare a sourced rule claim; no server-enforcement inference")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f.add_argument("--method", choices=sorted(HTTP_METHODS), required=True)
    f.add_argument("--location", choices=LOCATIONS, required=True)
    f.add_argument("--field", required=True)
    f.add_argument("--kind", choices=CONSTRAINT_KINDS, required=True)
    f.add_argument("--value", required=True, help="declared rule only; never a submitted secret")
    f.add_argument("--source", choices=CONSTRAINT_SOURCES, required=True)
    f.add_argument("--source-ref", required=True)
    f.add_argument("--response", type=int, help="stored rejection response for server-rejection claim")
    f = actions.add_parser("constraints")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f = actions.add_parser("surface-expect", help="declare an expected field x render x case")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f.add_argument("--field", required=True)
    f.add_argument("--surface", required=True)
    f.add_argument("--case", choices=SURFACE_CASES, required=True)
    f.add_argument("--source-ref", required=True)
    f.add_argument("--reason", required=True)
    f.add_argument("--account", default="")
    f.add_argument("--workflow", default="")
    f = actions.add_parser("surface-review", help="link a canary-captured render, or justify n-a")
    f.add_argument("campaign")
    f.add_argument("--expectation", type=int, required=True)
    f.add_argument("--state", choices=("reviewed", "n-a", "blocked", "inconclusive"), required=True)
    f.add_argument("--note", required=True)
    f.add_argument("--response", type=int)
    f = actions.add_parser("surfaces")
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
    s = sub.add_parser("authz", help="offline access-control and mass-assignment ledger; no traffic")
    actions = s.add_subparsers(dest="action", required=True)
    from .authz import CASES as AUTHZ_CASES, CHAIN as AUTHZ_CHAIN, STATES as AUTHZ_STATES, IMPACTS
    f = actions.add_parser("sync")
    f.add_argument("campaign")
    f = actions.add_parser("plan")
    f.add_argument("campaign")
    f.add_argument("--target", type=int)
    f.add_argument("--limit", type=int, default=25)
    f = actions.add_parser("record")
    f.add_argument("campaign")
    f.add_argument("--context", type=int, required=True)
    f.add_argument("--case", choices=(*AUTHZ_CASES, *AUTHZ_CHAIN), required=True)
    f.add_argument("--state", choices=AUTHZ_STATES, required=True)
    f.add_argument("--variant", default="default")
    f.add_argument("--grant", default="")
    f.add_argument("--parent", type=int)
    f.add_argument("--impact", choices=IMPACTS, default="none")
    f.add_argument("--marker", default="")
    f.add_argument("--proof-basis", default="")
    f.add_argument("--artifact", action="append", help="ROLE=campaign-relative path; baseline/test/control for proof")
    f.add_argument("--tool-ref", action="append", help="native:ID or burp:external-reference")
    f.add_argument("--requests", type=int, default=0, help="operator-declared external count, not traffic enforcement")
    f.add_argument("--owner", default="")
    f.add_argument("--root-key", default="", help="manual root-cause deduplication key")
    f.add_argument("--related-case", action="append", help="related case ID; repeatable")
    f.add_argument("--note", default="")
    f = actions.add_parser("status")
    f.add_argument("campaign")
    f.add_argument("--limit", type=int, default=100)
    f = actions.add_parser("verify")
    f.add_argument("campaign")
    s.set_defaults(fn=cmd_authz)
    s = sub.add_parser("authpolicy", help="offline auth-policy operations, rule contrasts and receipts")
    actions = s.add_subparsers(dest="action", required=True)
    from .authpolicy import ENTRY_CASES, STATES as AUTH_POLICY_STATES
    f = actions.add_parser("sync", help="inventory already-seen methods and contexts; no requests")
    f.add_argument("campaign")
    f = actions.add_parser("declare", help="declare an exact existing in-scope operation")
    f.add_argument("campaign")
    f.add_argument("--asset-id", type=int, required=True)
    f.add_argument("--url", required=True, help="exact endpoint without token-bearing query")
    f.add_argument("--method", choices=sorted(HTTP_METHODS), required=True)
    f.add_argument("--entry-point", choices=tuple(ENTRY_CASES), required=True)
    f.add_argument("--source-ref", required=True)
    for name in ("account", "role", "tenant", "workflow", "representation"):
        f.add_argument("--" + name, default="unknown")
    for action in ("plan", "status"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--limit", type=int, default=100)
        f.add_argument("--offset", type=int, default=0)
        if action == "plan":
            f.add_argument("--operation", type=int)
    f = actions.add_parser("record", help="label stored response contrasts; never promotes a finding")
    f.add_argument("campaign")
    f.add_argument("--operation", type=int, required=True)
    f.add_argument("--case", required=True, help="exact case key from authpolicy plan, including rule hash")
    f.add_argument("--state", choices=AUTH_POLICY_STATES, required=True)
    f.add_argument("--ref", action="append", help="ROLE:stored-response-ID (repeatable)")
    f.add_argument("--note", required=True, help="bounded value-free label; never cookies/tokens")
    f.add_argument("--source", choices=("import", "native", "browser-burp", "owned-lab"), default="import")
    f = actions.add_parser("derive", help="transient structural sample analysis, never stores values")
    f.add_argument("campaign")
    f.add_argument("--file", required=True, help="mode 0600 campaign-relative .recon/private/auth-policy/ JSON")
    f = actions.add_parser("verify", help="recheck hashes, scope, policy and evidence references")
    f.add_argument("campaign")
    f.add_argument("--limit", type=int, default=100)
    f.add_argument("--offset", type=int, default=0)
    s.set_defaults(fn=cmd_authpolicy)
    s = sub.add_parser("upload", help="offline file-upload lifecycle ledger and inert fixtures; no traffic")
    actions = s.add_subparsers(dest="action", required=True)
    from .upload import (CALLBACK_KINDS, CASES as UPLOAD_CASES, CHANNELS, CLEANUP_OUTCOMES,
                         FIXTURE_KINDS, LAYERS, ROUTES, STATES as UPLOAD_STATES, STOP_KINDS,
                         SURFACES, TRANSPORTS)
    f = actions.add_parser("sync", help="reconcile captured/declared upload sinks and contexts")
    f.add_argument("campaign")
    f = actions.add_parser("declare", help="record an in-scope upload operation seen in Burp or "
                                           "source review (signed storage, URL import, resumable)")
    f.add_argument("campaign")
    f.add_argument("--url", required=True)
    f.add_argument("--method", default="POST")
    f.add_argument("--field", required=True, help="file field name, or a (placeholder) such as (body)")
    f.add_argument("--transport", choices=TRANSPORTS, required=True)
    f.add_argument("--surface", choices=SURFACES, default="")
    f.add_argument("--note", required=True, help="where it was observed, e.g. a Burp history label")
    f = actions.add_parser("plan", help="per-sink contexts with 24 lifecycle case cards")
    f.add_argument("campaign")
    f.add_argument("--sink", type=int)
    f.add_argument("--limit", type=int, default=25)
    f = actions.add_parser("fixture", help="write one tiny inert marker fixture plus a distinct control")
    f.add_argument("campaign")
    f.add_argument("--kind", choices=FIXTURE_KINDS, required=True)
    f.add_argument("--size", type=int, help="text fixtures only; at most 4096 bytes")
    f = actions.add_parser("record", help="append one case event with stage facts and hash-bound artifacts")
    f.add_argument("campaign")
    f.add_argument("--context", type=int, required=True)
    f.add_argument("--case", choices=list(UPLOAD_CASES), required=True)
    f.add_argument("--state", choices=UPLOAD_STATES, required=True)
    f.add_argument("--channel", choices=CHANNELS, default="browser")
    f.add_argument("--grant", default="")
    f.add_argument("--marker", default="")
    f.add_argument("--control-marker", default="")
    f.add_argument("--fact", action="append", help="STAGE=yes|no for accepted, stored, reachable, "
                                                   "processed, served, executed, effect")
    f.add_argument("--artifact", action="append", help="ROLE=campaign-relative path; repeatable")
    f.add_argument("--layer", choices=LAYERS, default="unconfirmed")
    f.add_argument("--request-ref", default="", help="request ID that the layer log must contain")
    f.add_argument("--response-status", type=int)
    f.add_argument("--route", choices=ROUTES, default="")
    f.add_argument("--stop-trigger", choices=STOP_KINDS, default="")
    f.add_argument("--served-headers", help="JSON object of retrieval response headers")
    f.add_argument("--requests", type=int, default=0, help="declared requests; native must cite IDs")
    f.add_argument("--bytes", type=int, default=0, help="declared uploaded bytes")
    f.add_argument("--objects", type=int, default=0, help="owned objects created; need cleanup")
    f.add_argument("--object-ref", default="")
    f.add_argument("--tool-ref", action="append", help="native:ID or burp:label")
    f.add_argument("--root-key", default="")
    f.add_argument("--note", default="")
    f = actions.add_parser("callback", help="correlate receiver evidence with one attempt")
    f.add_argument("campaign")
    f.add_argument("--event", type=int, required=True)
    f.add_argument("--kind", choices=CALLBACK_KINDS, required=True)
    f.add_argument("--url", required=True, help="receiver URL, or receiver hostname for dns")
    f.add_argument("--sent-at", required=True)
    f.add_argument("--observed-at", required=True)
    f.add_argument("--deadline", required=True)
    f.add_argument("--control-marker", required=True)
    f.add_argument("--health", choices=("ok", "failed"), default="ok")
    f.add_argument("--job-id", default="")
    f.add_argument("--artifact", action="append", help="receiver-health=, receiver-log=, worker-log=")
    f.add_argument("--note", default="")
    f = actions.add_parser("cleanup", help="record deletion/abort/expiry receipts for an attempt")
    f.add_argument("campaign")
    f.add_argument("--event", type=int, required=True)
    f.add_argument("--outcome", choices=CLEANUP_OUTCOMES, required=True)
    f.add_argument("--artifact", default="")
    f.add_argument("--note", default="")
    f = actions.add_parser("resume", help="clear a host stop after review")
    f.add_argument("campaign")
    f.add_argument("--host", required=True)
    f.add_argument("--note", required=True)
    f = actions.add_parser("status")
    f.add_argument("campaign")
    f.add_argument("--limit", type=int, default=100)
    f = actions.add_parser("verify")
    f.add_argument("campaign")
    s.set_defaults(fn=cmd_upload)
    s = sub.add_parser("ssti", help="offline SSTI arithmetic probes and raw-surface evidence; no execution")
    actions = s.add_subparsers(dest="action", required=True)
    from .ssti import (CASES as SSTI_CASES, DEPTH_GRANTS as SSTI_GRANTS,
                       READ_ONLY_METHODS, STATES as SSTI_STATES, SURFACE_KINDS)
    f = actions.add_parser("probes", help="create/reuse a field-context probe set, or show an existing set")
    f.add_argument("campaign")
    f.add_argument("--set", dest="set_id", type=int)
    f.add_argument("--asset-id", type=int)
    f.add_argument("--field")
    f.add_argument("--method", default="")
    f.add_argument("--location", default="unknown")
    f.add_argument("--account", default="")
    f.add_argument("--role", default="")
    f.add_argument("--tenant", default="")
    f.add_argument("--workflow", default="")
    f.add_argument("--compact", action="store_true")
    f = actions.add_parser("surface", help="declare a separate server-rendered or DOM surface")
    f.add_argument("campaign")
    f.add_argument("--set", dest="set_id", type=int, required=True)
    f.add_argument("--kind", choices=SURFACE_KINDS, required=True)
    f.add_argument("--label", required=True)
    f = actions.add_parser("trace", help="classify one stored response or campaign-local artifact")
    f.add_argument("campaign")
    f.add_argument("--surface", dest="surface_id", type=int, required=True)
    f.add_argument("--probe", required=True)
    f.add_argument("--response", type=int)
    f.add_argument("--artifact")
    f = actions.add_parser("record", help="append evidence-gated detect/confirm/stored/severity event")
    f.add_argument("campaign")
    f.add_argument("--surface", dest="surface_id", type=int, required=True)
    f.add_argument("--case", choices=SSTI_CASES, required=True)
    f.add_argument("--state", choices=SSTI_STATES, required=True)
    f.add_argument("--note", required=True)
    f.add_argument("--severity", choices=("low", "medium", "high", "critical"),
                   help="severity-gate only; evaluation alone is capped at medium")
    f.add_argument("--grant", choices=SSTI_GRANTS,
                   help="depth cases only; must match ssti.depth_grants")
    f.add_argument("--target",
                   help="depth cases only: listed data path, in-scope read-only URL, or callback host")
    f.add_argument("--exercise", type=str.upper, choices=READ_ONLY_METHODS,
                   help="token-use only: the single read-only method exercised")
    f.add_argument("--attempts", type=int, default=0,
                   help="depth cases only: declared attempts (0..1; observed needs 1)")
    f.add_argument("--artifact", action="append", default=[],
                   help="depth cases only: campaign-local evidence artifact (repeatable)")
    for action in ("fingerprint", "plan", "status"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--set", dest="set_id", type=int, required=True)
    f = actions.add_parser("verify", help="rehash every stored capture and artifact reference")
    f.add_argument("campaign")
    s.set_defaults(fn=cmd_ssti)
    s = sub.add_parser("cache", help="offline cache poisoning/deception evidence ledger; "
                                      "no priming, purge or cache executor")
    actions = s.add_subparsers(dest="action", required=True)
    f = actions.add_parser("record", help="append one hash-bound cache event from a "
                                          "campaign-relative schema-1 JSON file")
    f.add_argument("campaign")
    f.add_argument("--file", required=True, help="campaign-relative event JSON")
    f = actions.add_parser("show", help="stored-response snapshot plus its cache events")
    f.add_argument("campaign")
    f.add_argument("--reference", type=int, required=True, help="stored request ID")
    f = actions.add_parser("status")
    f.add_argument("campaign")
    f.add_argument("--limit", type=int, default=25)
    f = actions.add_parser("verify", help="rehash events, artifacts and referenced stored responses")
    f.add_argument("campaign")
    f = actions.add_parser("import", help="read a local HAR/Burp export or raw-pair manifest; no replay")
    f.add_argument("campaign")
    f.add_argument("--file", required=True)
    f.add_argument("--format", choices=("har", "burp-xml", "burp-json", "raw-pair"), required=True)
    for name in ("account", "role", "tenant", "workflow"):
        f.add_argument("--" + name, default="unknown")
    for action in ("profile", "isolation"):
        f = actions.add_parser(action, help="record a campaign-local schema-1 review declaration")
        f.add_argument("campaign")
        f.add_argument("--file", required=True)
    f = actions.add_parser("review", help="sanitized capture/profile/isolation review by journal ID")
    f.add_argument("campaign")
    f.add_argument("--id", type=int, required=True)
    for action in ("reviews", "verify-reviews"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--limit", type=int, default=100)
        f.add_argument("--offset", type=int, default=0)
        if action == "reviews":
            f.add_argument("--kind", choices=("capture", "profile", "isolation"))
    s.set_defaults(fn=cmd_cache)
    s = sub.add_parser("http-review", help="offline conservative HTTP/1 framing lint; "
                                           "not a smuggling detector or raw transport")
    actions = s.add_subparsers(dest="action", required=True)
    f = actions.add_parser("inspect", help="inspect one captured message without forwarding it")
    f.add_argument("campaign")
    f.add_argument("--file", required=True, help="campaign-relative raw HTTP/1 file")
    f.add_argument("--url", required=True, help="capture origin/target attribution, never fetched")
    f.add_argument("--kind", choices=("request", "response"), default="request")
    f = actions.add_parser("show")
    f.add_argument("campaign")
    f.add_argument("--id", type=int, required=True)
    for action in ("status", "verify"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--limit", type=int, default=100)
        f.add_argument("--offset", type=int, default=0)
    s.set_defaults(fn=cmd_http_review)
    s = sub.add_parser("rce", help="offline source-qualified sink and owned-lab evidence review; "
                                 "no payloads, traffic or finding promotion")
    actions = s.add_subparsers(dest="action", required=True)
    for action in ("declare", "record"):
        f = actions.add_parser(action, help="import a campaign-relative schema-1 " +
                               ("sink declaration" if action == "declare" else "evidence receipt"))
        f.add_argument("campaign")
        f.add_argument("--file", required=True)
    f = actions.add_parser("show")
    f.add_argument("campaign")
    f.add_argument("--id", required=True, type=int)
    for action in ("status", "verify"):
        f = actions.add_parser(action)
        f.add_argument("campaign")
        f.add_argument("--limit", type=int, default=100)
        f.add_argument("--offset", type=int, default=0)
    s.set_defaults(fn=cmd_rce)
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

    s = sub.add_parser("exec", help="run one allowlisted external tool under recon's scope, "
                                     "methods, pacing and shared campaign budget")
    s.add_argument("campaign")
    s.add_argument("--tool", required=True, choices=sorted(PROFILES),
                   help="allowlisted tool profile; direct invocation stays refused")
    s.add_argument("--engagement", required=True,
                   help="engagement id the run is charged to; its blocked hosts are enforced")
    s.add_argument("--estimate", type=int, required=True,
                   help="declared request estimate, pre-charged to the campaign budget and "
                        "never refunded; it also sets the wall-clock cap")
    s.add_argument("--plan", action="store_true",
                   help="validate scope, methods, flags and budget and print the plan; launch nothing")
    s.add_argument("--no-import", action="store_true",
                   help="keep the artifact but skip the offline surface import")
    # `--` is required before the tool's own flags: without it argparse would read
    # them as recon's, and a REMAINDER positional would swallow recon's own options.
    s.add_argument("args", nargs="*",
                   help="after --, the tool's own arguments (rate, output and cap flags are injected)")
    s.set_defaults(fn=cmd_exec)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (ConfigError, ValueError, KeyError, OSError, PolicyViolation, OutOfScope) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
