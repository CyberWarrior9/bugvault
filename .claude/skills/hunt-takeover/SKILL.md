---
name: hunt-takeover
description: "Investigate subdomain/domain takeover on authorized BugVault campaigns. Load for every subdomain-takeover coverage row, dangling DNS/provider signal, NS referral mismatch, wildcard ambiguity, stale trusted hostname or proposed resource claim. Use offline recon takeover imports and provenance graphs to separate DNS observations, dated provider confidence, namespace availability, conditional trust chains, owned marker proof and cleanup. Always use this skill before ranking or accepting a takeover claim: suffixes, error pages, missing addresses and parent-app trust references never confirm a finding. No automatic claiming, live DNS collector or provider-freshness guarantee."
license: "MIT; original BugVault workflow. External concepts are referenced, not substantially copied."
metadata:
  implementation: "recon/takeover.py offline ledger; no target executor or resource-claim automation"
  reviewed: "2026-11-16"
---

# Hunt: forgotten but still trusted hostnames

Read `scope-policy`, the campaign's written rules and `scope.json` first. A DNS
dependency, certificate, coverage row or provider match never expands authorization.
Work on operator-owned test accounts/resources only. The unit of work is **one
hostname/delegation and its dated evidence**, not a provider brand or an entire zone.

## Authorization and execution boundary

`takeover.rules_reviewed` is the date the published rules were reviewed;
`takeover.grants` is a list containing only the approved `claim` and/or `chain`
evidence families; `takeover.budget` is an integer declaration. These are
**evidence-recording gates only**, not permission to register, deploy or send traffic.
Live evidence also needs the program permission/source, campaign scope, mode,
allowed methods, remaining budgets and a separately approved execution plan.
Keep permission for a program hostname distinct from permission to use its provider.

The dedicated visible browser through Burp is the default live path. Read
`.claude/skills/scope-policy/references/browser-workflow.md` and
`.claude/skills/scope-policy/references/burp-workflow.md` before any external action.
Interactive provider login/signup and test-mailbox work use only that prepared,
connected profile; preparation alone is not connectivity or capture verification.
A standing campaign plan may separately permit scoped native requests or
operator-run scanners. Native requests use `python3 -m recon send`; it is **not** a
DNS collector, provider account client or claim executor. Burp sends/preparation,
Collaborator and settings changes need explicit operator approval and manual shared
scope/rate/budget accounting. Missing tools or a failed check grants no alternate path.

## Offline workflow: five passes

1. **Inventory DNS breadth and ambiguity.** Import a bounded, operator-supplied
   normalized schema-1 capture with `python3 -m recon takeover import <campaign>
   <file>`. Preserve A/AAAA/CNAME/NS/MX/TXT/SOA, resolver/time, response status,
   parent referrals versus child/recursive answers and wildcard controls. Missing
   observations remain unknown. Read [record types](references/record-types.md).
    This command does not run DNS queries, follow referrals or guess DKIM selectors.
    Before import, explicitly map existing raw observations to the installed
    `recon/takeover_dns.py` schema and validate them offline. If only chat summaries
    exist or a required result/resolver/time is missing, describe normalization as
    blocked; do not invent a status or claim an import/verification succeeded.
2. **Separate provider identification from confidence.** Use
   `python3 -m recon takeover sync <campaign>` to reconcile stored evidence, then
   `python3 -m recon takeover plan <campaign>` and
   `python3 -m recon takeover show <campaign> --candidate N`. Record the provider
   source/version, status, review date and namespace evidence separately. A suffix,
   unclaimed-looking response, NXDOMAIN or empty A answer is not claimability.
   Historical/unknown provider data stays historical/unknown; read
   [provider confidence](references/providers.md).
3. **Rank conditional chains, not severity.** Review the exact captured CSP,
   cookie, CORS, OAuth, HSTS and mail references **before any claim**. A stale host
   still referenced by production can deserve investigation ahead of an isolated
   dangle while its claim branch remains blocked. Preserve response/artifact refs
   and missing preconditions; read [chain rules](references/chains.md). A CSP
   allowlist is not an injection point; a public-suffix guess is not cookie policy.
4. **Preserve hostname lifecycle.** Trace CT, archive, imported DNS and current/old
   JS/HTML sightings with source hashes, first/last capture times, certificate dates
   when supplied, DNS history, HTTP observations and reverse production references.
   Read [lifecycle](references/lifecycle.md). `sync` only analyzes stored inputs:
   it neither resolves extracted names nor queues new target traffic. Out-of-scope
   names stay intel-only; a bounded discovery graph is not a complete zone inventory.
5. **Prepare a claim dossier or an owned rehearsal.** Bind the candidate snapshot,
   precheck, provider requirements, namespace check, owned resource/account,
   permission, independent before/after/replay/control evidence, TLS where needed,
   cleanup owner/deadline and any downstream proof. Read
   [evidence](references/evidence.md) before serializing a JSON event and
   [owned rehearsal](references/rehearsal.md) before describing a lab result.
   Claiming remains an explicitly approved operator action, never an automatic next
   step. With no grant/path, retain a blocked dossier and its evidence.

## Record, verify and clean up

Every triage handoff should explicitly include **normalization readiness**: name
the installed DNS/event schema, say which supplied observations can be normalized
and validated offline, and list any missing required fields/raw captures. With only
summaries, report that import/verification has not happened and describe the
schema-bound normalization handoff as pending or blocked. Keep this separate from
claimability, conditional impact, execution permission and cleanup readiness so a
careful risk assessment cannot accidentally omit the evidence-import handoff.

```bash
python3 -m recon takeover record <campaign> --file event.json
python3 -m recon takeover cleanup <campaign> --file cleanup.json
python3 -m recon takeover status <campaign>
python3 -m recon takeover verify <campaign>
```

All commands above are offline. The normalized DNS and JSON event wire schemas
are defined by `recon/takeover.py` and its DNS validator, not arbitrary raw DNS,
scanner or Burp exports. Inspect the installed implementation before generating
files; do not invent accepted keys, response IDs or successful integrity checks.
`verify` checks stored integrity; `show`/`status` expose snapshot staleness. Neither
checks present-day DNS, provider availability, TLS validity or exploit causality.
A schema-valid event is still an operator assertion.

Keep baseline, claimed-host marker response, fresh replay and a **distinct negative
control** separate. A marker at the provider's own URL does not establish control
of the program hostname. A before-image is not by itself a distinct negative control.
HTTPS 200 or a response header is not certificate validation; preserve exact-name,
chain/trust, validity, SNI and approved browser evidence where the chain requires TLS.
Account for proxy interception rather than mistaking Burp's certificate for origin proof.

Cleanup needs provider release/deletion or owner-retention instruction, exact owned
resource binding and a post-cleanup check. Deleting an account screenshot, planning
deletion or waiting for a TTL is not a receipt. Do not alter the program's DNS unless
separately authorized. Failed/unverified cleanup stays open and blocks further live
work; coordinate retention with the program rather than silently releasing a dangerous
dangle. Never erase inconclusive or historical evidence to make status look complete.

## Stops, handoffs and hard limits

- Stop on exhausted budgets, challenges, 429/5xx, degradation, unexpected cost,
  unapproved destinations, real-user data or unresolved cleanup. Record blocked or
  inconclusive with a reason; there is no implicit retry/resume or alternate client.
- No automatic registration/resource allocation, domain purchase, address-pool
  reacquisition, certificate issuance, provider login, DNS brute force, mail
  interception or mail sending. Do not take over nameservers, redirect real traffic
  or receive real users' sessions/messages to demonstrate an impact hypothesis.
- An NS mismatch is not zone control, a wildcard is not takeover generation by
  itself, and MX/SPF/DKIM dependencies do not establish authenticated mail control.
- Route separately demonstrated browser script execution to `hunt-xss`, OAuth
  flow proof to `hunt-oauth`/`hunt-ato`, cross-origin read to `hunt-access-control`,
  and same-site request effects to `hunt-csrf`. Use supplied A/V accounts, shared
  lineage and each class's proof gate; do not file five impacts from five headers.
- Candidate states never mean finding `confirmed`. Keep replay, distinct negative
  control, demonstrated impact and the existing validator/reportability gate.
  Dangling-DNS-only reporting depends on the particular program's written rules.
- Minimize/redact private artifacts, credentials and cookie values. Do not switch
  models for tools or broadcast raw traffic/provider data to other model providers.

Provenance, external reference URLs and corrections to the supplied proposal:
[sources](references/sources.md). Judgment cases live in `evals/`; they are not
executed tests or evidence of full provider/record-type coverage.

Disclosed-report precedent for this class — scale, highest-bounty disclosures and
corpus queries: [references/corpus.md](references/corpus.md). Precedent, not evidence:
a disclosed report shows a bug was accepted somewhere, never that this target has it.
