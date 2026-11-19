# Takeover workflow acceptance — 2026-11-16

Plan: [`plans/subdomain-takeover.md`](../plans/subdomain-takeover.md).
Skill: [`hunt-takeover`](../.claude/skills/hunt-takeover/SKILL.md).

## Outcome and scope

The new workflow is an **offline evidence and prioritization implementation**, not
a live takeover scanner or automatic claimer. No target/provider/DNS/browser action
was performed. Existing unrelated working-tree changes and vault outputs were
preserved. The two protected temporary upload/business-race plans were not edited.

| Planned work | Implemented | Acceptance limits |
|---|---|---|
| DNS breadth | Typed A/AAAA/CNAME/NS/MX/TXT/SOA captures, explicit errors, parent/child referral comparison, same-resolver/time wildcard controls and literal mail dependencies | Operator-supplied normalized capture only; no DNS collector, DNSSEC validator, complete zone enumeration or IP-pool claimability |
| Auditable candidates | Source hashes, DNS histories, latest-observation projection, provider source/status/date, 90-day freshness, collection gaps and inactive history | Provider records are assertions; no provider is certified claimable today. Normal addresses/SOA do not seed takeover claims |
| Conditional impact | Exact-host CSP/cookie/CORS/OAuth/HSTS references, reverse mail edges, host coverage, skill/catalog/report/chain routing | No CSP entry implies script loading, cookie implies session, CORS header implies read or redirect reference implies accepted allowlist |
| Stale-host discovery | CT dates when supplied, imported/archived assets and JS/HTML references, source-qualified sightings, reverse references, dated DNS and captured HTTP metadata | Stored evidence only; no new host resolution/queueing, broader passive provider, brute force or exhaustive inventory |
| Claim dossier/rehearsal | Precheck/claimability prerequisites, candidate-host JSON receipts, marker/control differences, declared live grant/budget gates, owned labels, cleanup deadline/resource receipt | Operator evidence recording only; validator judges chronology/ownership/causality. Lab is an in-memory provider simulation, not cloud/DNS/TLS/browser proof |

## Gates

### A — deterministic regressions

Focused tests cover normalized schema/limits, IDNA/unsafe names, address families,
resolver/time disagreement, referrals, wildcard depth, provider freshness/conflicts,
mail references, scope/intel separation, repeated imports, source/body/artifact
tampering, current snapshot gates, conditional ranking, CT dates, archived context,
live recording permissions/budget and no automatic findings or network activity.
CLI, report, catalog and skill routing are checked. The first full regression run
passed **625 tests**; final verification is recorded below after the last changes.

### B — owned simulation

`tests/test_recon_takeover_lab.py` runs an in-process A/B provider allocator:
deploy A, delete A, refuse B on an occupied control, precheck, inspect simulated
availability, reclaim as B, serve an inert marker, retain before/after/distinct
negative control, release and verify the simulated resource is gone. It rejects
missing/contaminated controls, provider-only marker receipts and unrelated cleanup.
Network/subprocess/provider/browser paths are explicitly guarded in those tests.
There is no externally allocated resource and no TLS/browser/mail certification.

### C — model judgment (limited)

Three fictional cases cover NS/referral false positives, trusted stale-host ranking
and claim/cleanup proof. Iterations 1 and 2 each passed **17/18 assertions**; after
requiring a separate normalization-readiness handoff, iteration 3 passed **18/18**.
Attempted without-skill runs
consulted mandatory repository guidance, so they are **invalid baselines**, not
evidence of causal improvement. The primary-only rerun and review artifacts are
listed below. Single-sample semantic grades are not broad performance assurance;
no timing/token statistics or execution-trace claims are manufactured.

Review artifacts are private generated files under
`.recon/skill-evals/hunt-takeover/iteration-1/`, `iteration-2/` and `iteration-3/`, including
assessments, grader evidence, metadata and static `review.html`. Invalid baselines
are retained with validity labels, not erased or included in the scored benchmark.

## Operational bounds and unresolved work

An independent read-only code review found ten gaps beyond the initial green
suite. Regression fixes now cover campaign-wide failed/overdue cleanup stops,
excluded-class policy snapshots, once-read validation/copy bytes, exact candidate
identity binding, response-body rather than request-metadata markers, full live
receipt URL scope checks, elapsed provider freshness, exact structured cleanup
resource equality, dependency-scoped snapshots, retirement of resolved legacy
leads and once-per-input capture verification. The final review recheck is recorded
below; these are software-ledger checks, not independent exploit validation.

- Campaign DNS history is capped at **2,000 unique normalized observations**;
  oversize additions fail before import writes. JSON input <=2 MB; evidence
  artifacts <=5 MB; graph sync scans at most 2,000 assets and 2,000 responses.
  Bounded output and scans must never be described as exhaustive coverage.
- Live claim evidence requires DNS captured within 24 hours, negative comparable
  wildcard controls and reviewed, non-stale `vulnerable` provider status. Unknown,
  patched or edge-case provider status remains blocked for live success records.
  Unknown provider products/NS claim paths remain blocked rather than guessed.
- The grant/budget ledger is not external traffic enforcement or an atomic
  cross-process reservation mechanism. Burp/scanner/provider accounting remains
  operator-reviewed; existing execution policy and approvals still apply.
- Complete PSL-based cookie/site classification, current provider-specific owned
  rehearsals, HTTPS certificate validation, connected dedicated browser/Burp,
  approved DNS collection and a real scoped pilot remain untested follow-ons.
- `inventory_complete` and `coverage_complete` deliberately remain false. A coarse
  coverage status cannot substitute for these evidence/validator requirements.

## Final verification

- `.venv/bin/python -m unittest discover -s tests -q`: **674 passed, 0 skipped**,
  52.501 seconds. This is 129 additional tests over the recorded 545-test baseline.
  Saved output: `.recon/skill-evals/hunt-takeover/full-suite.txt`. Two printed
  CLI error lines are expected negative-test assertions, not suite failures.
- Focused takeover/parser/evidence/lab/review/skill/chain command: **175 passed**.
- Independent review recheck: all ten original reproductions resolved; **49 existing
  review/ledger/lab tests** and **11 additional offline probes** passed. Valid
  controls succeeded; rejected evidence left event/cleanup rows unchanged. A
  200-observation capture is read once per verification, and later tampering fails.
- Synthetic example `tests/fixtures/recon/takeover-capture.json`: validated offline;
  incomplete wildcard/failed address evidence remains `collection-gap`.
- `git diff --check -- . ':!vault/_data/reports.csv'`: passed. The excluded CSV has
  pre-existing CRLF warnings unrelated to this work. No commit or push performed.
- Judgment iterations 1 and 2 each scored **17/18**: the NS dossier omitted an
  explicit installed-schema normalization handoff. The skill now requires a
  separate normalization-readiness section in every triage handoff. Iteration 3
  scored **18/18** (6/6 in each case), independently graded against the unchanged
  assertions. These are output-only judgments of fictional scenarios, not trace-
  certified execution, actual imported evidence or a causal improvement benchmark.
  Human review remains available in
  [the final static review](../.recon/skill-evals/hunt-takeover/iteration-3/review.html).
