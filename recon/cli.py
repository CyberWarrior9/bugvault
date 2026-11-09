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

<campaign> is a name under vault/10-Campaigns/ or a path to a folder with scope.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .campaign import Campaign, ConfigError, MODES, OutOfScope, scope_template

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
    root.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps(scope_template(a.program or root.name, a.seed, a.mode), indent=2)
                   + "\n")
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
                       use_searchsploit=not a.no_searchsploit)
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
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (ConfigError, ValueError, KeyError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
