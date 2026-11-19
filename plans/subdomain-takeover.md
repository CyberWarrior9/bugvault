# Subdomain takeover: implementation and acceptance plan

Date: 2026-11-16. Baseline: 545 tests reported passing before this change.
This supersedes the proposal in `/tmp/plan_subdomain_takeover.md`, without changing it.

## Goal and boundaries

Find forgotten but still trusted hostnames, distinguish broken DNS from resource
claimability, and prepare evidence-backed operator claim/chain dossiers. Extend the
existing CNAME/body lead detection, do not replace it with automatic confirmation.
All new commands are offline. No automated domain/resource registration, provider
login, DNS brute force, certificate issuance, mail interception or target executor.
Existing campaign scope, exclusions and execution policy remain authoritative.
New ledger grants authorize evidence recording, not traffic or external actions.

## Five work packages

1. **DNS breadth and referrals.** Import bounded schema-1 operator captures for
   A/AAAA/CNAME/NS/MX/TXT/SOA, explicit NXDOMAIN/NODATA/SERVFAIL/timeout states,
   resolver/time, parent referral versus child answer, wildcard controls and
   SPF/DKIM references. Missing records are unknown, not negative. An NS mismatch,
   wildcard or missing address does not establish claimability. No guessed DKIM
   selectors or address-pool allocation attempts.
2. **Auditable candidates.** Preserve capture hashes and immutable observations;
   provider match, dated source/status and namespace availability are separate
   facts. Freshness, collection gaps and wildcard ambiguity block stronger claims.
   Provider suffixes and error-page strings only identify leads. No automatic
   finding promotion; retain existing replay/control/validator gates.
3. **Conditional impact ranking and integration.** Parse captured CSP, cookies,
   CORS, HSTS, OAuth redirect references and DNS mail dependencies. Rank trusted
   stale hosts ahead of isolated dangles. Persist exact response/artifact references;
   trust edges remain conditional. Seed takeover coverage on host/zone assets,
   route to hunt-takeover, expose CLI/report/catalog and add conditional chain hints.
4. **Stale-host discovery graph.** Merge CT/archive/imported host assets and
   bounded current/archived JS/HTML references from stored bodies. Preserve source,
   first/last sightings, certificate dates when supplied, DNS history, HTTP status
   and reverse production-reference edges. Out-of-scope names remain intel only;
   graph sync never queues or resolves a newly extracted name. Discovery is not an
   exhaustive zone inventory. Repeated identical evidence deduplicates.
5. **Claim dossier and owned rehearsal.** Bind candidate, provider requirements,
   namespace check, owned account/resource, program permission, before/after marker,
   separate negative control, TLS evidence where applicable, cleanup owner/receipt
   and downstream proof. Enforce precheck-before-claim and fail-closed live evidence
   grants/budgets. Run a local simulated provider lifecycle (deploy/delete/reclaim/
   marker/release); do not describe it as a real cloud-provider or browser TLS test.

## Intended implementation

- `recon/takeover_dns.py`: pure capture validation/classification and provider status.
- `recon/takeover_trust.py`: pure exact-host trust-reference extraction.
- `recon/takeover.py`: offline graph/candidate/event ledger, integrity, ranking,
  claim dossier and cleanup tracking.
- `recon takeover import|sync|plan|show|record|cleanup|status|verify`.
- `.claude/skills/hunt-takeover/`: procedure, schemas, chains, sources and eval cases.
- Host/zone coverage wiring, catalog, report and chain hints; fix legacy cookie
  context matching without treating public-suffix guesses as authority.

## Acceptance gates

**A — deterministic regressions:** schema/size/hostname validation; scope and
exclusions; DNS errors versus absence; referrals; wildcard controls; fingerprint
freshness; idempotence; discovery provenance/timeline; exact-host CSP/CORS/OAuth
and cookie semantics; response/artifact tamper detection; grant, budget, marker,
precheck and cleanup failures; no automatic findings or new target traffic;
CLI/catalog/skill/coverage/report integration. Run full existing suite too.

**B — owned lab:** simulated provider lifecycle and before/after/control evidence,
negative claimed-resource case, cleanup, and conditional parent trust observations.
No external DNS/provider calls. This cannot certify provider-specific claimability,
certificate validation, browser behavior, real mail control or a live chain.

**C — skill judgment:** paired with/without-skill runs for NS false positives,
trusted stale-host prioritization and claim/chain evidence. Save outputs, assertions
and an HTML review artifact; do not equate small model evals with full coverage.

## Explicit follow-on work, not acceptance claims

- Budgeted live DNS collectors (`dnsrecords`/`dnsreferral`) integrated with scoped
  execution, DNS query accounting and approved external nameserver access.
- Independent, current provider catalogue review and authorized provider-specific
  owned-account rehearsal; no hardcoded provider is certified claimable today.
- Operator-supplied complete zone exports and broader CT/passive sources.
- Connected dedicated browser/Burp verification, HTTPS/certificate and real
  cloud-provider cleanup, followed by a separately approved live pilot.
- Full PSL-based registrable-domain analytics if unavailable locally; cookie
  domain-match is implemented directly and does not guess eTLD+1.

## Results

Implemented the bounded offline work packages and skill, with explicit live
collection/provider/browser follow-ons still deferred. The full regression command
`.venv/bin/python -m unittest discover -s tests -q` passed **674 tests, 0 skipped**
after independent-review fixes. Focused takeover/skill/chain regressions passed
**175 tests**. The final three-case skill judgment run passed **18/18 assertions**;
invalid attempted baselines are explicitly excluded (no causal improvement claim).
The owned provider rehearsal and sample DNS capture are synthetic; no live target
was tested or resource claimed. See
[`docs/takeover-acceptance.md`](../docs/takeover-acceptance.md) for exact gate results,
model-judgment limitations, invalid attempted baselines and remaining acceptance
work. This does not certify full DNS coverage, current provider claimability or
live impact.
