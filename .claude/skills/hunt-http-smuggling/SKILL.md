---
name: hunt-http-smuggling
description: "Review HTTP request smuggling and desynchronization in authorized BugVault work. Load for http-smuggling coverage rows, CL.TE/TE.CL/TE.TE or CL.0/0.CL findings, HTTP/2-to-HTTP/1 downgrade ambiguity, client-side desync, request tunnelling, or response-queue misassociation. Start with offline captures and parser/connection evidence; distinguish a timing anomaly from an attributed boundary disagreement and an owned security effect. Do not use for ordinary slow requests, HTTP parameter pollution, or response-header injection without a request-boundary question."
license: "MIT; original BugVault workflow. Research concepts referenced, no external payloads or tool code imported."
metadata:
  implementation: "Skill and operator-designated coverage routing only; no smuggling ledger, raw transport, scanner or target executor"
  reviewed: "2026-11-20"
---

# Hunt: HTTP request boundaries and desync

Establish **which implementations disagree, on which bytes, on which hop**.
A timeout, a 400/502, an HTTP/2 advertisement or a scanner alert is a lead,
not smuggling. Timing probes can affect shared connections; they are not safe
by construction. Use offline evidence or an isolated owned lab by default.

## Plan and boundaries

1. Before any external
   exercise, require the standing campaign execution plan to explicitly cover
   desync, exact origin/port/paths and methods, owned A/B contexts, isolated
   backend connection pool, protocol/tool/version, counts, window, stop conditions
   and a cleanup owner. A test account or low request rate does not isolate a
   shared pool. Missing authorization or isolation → blocked live work; continue
   offline review, not an alternative transport.
2. Review [cases](references/cases.md) for the relevant family. Read
   [evidence](references/evidence.md) before classifying any result. Record
   unknown topology, protocol conversion, connection reuse or capture fidelity
   explicitly; do not fill them from a vendor/version suitability table.
3. Inventory the test unit: origin + exact route + client/front-end/upstream
   protocols + suspected parser pair + connection/pool + owned context + family.
   Browser/client-side cases may involve one server and a browser connection;
   do not require a proxy pair for those. An HTTP/2 stream is not a separate TCP
   connection; out-of-order responses on different streams are normal.
4. Review a clean baseline, candidate exchange, separately owned follow-up,
   fresh-state replay, matched negative control and benign positive control.
   The follow-up must omit the trigger. Attribute any residual-byte consumption
   or response misassociation to connection/stream and hop evidence. Identical
   markers, reordered responses or a changed status alone do not establish this.
5. Only recommend a separately approved, human-operated isolated exercise when
   evidence is missing.
   Follow `.claude/skills/scope-policy/references/burp-workflow.md` for approvals
   and external accounting. No target executor is added by this skill.
6. Separate the verdicts: observed syntax/timing fact → attributed boundary
   disagreement → owned cross-request effect → validated security impact.
   Keep `blocked`, `inconclusive`, exact-case `negative` and `observed` separate.
   These are review labels, not an installed ledger schema. A negative on one
   route/protocol/pool does not close another, and an effort cap is not coverage.

## Available BugVault surfaces

- `python3 -m recon check <campaign> <url>` checks each intended URL offline.
  Check every outer and embedded/follow-up target independently, including
  encoded spellings, methods and exclusions; scope normalization is not evidence
  that a proxy parses those bytes the same way.
- `python3 -m recon responses <campaign>` lists existing stored responses.
  `python3 -m recon fact check` verifies narrow stored predicates, not framing,
  connection reuse, parser disagreement or vulnerability confirmation.
- `python3 -m recon http-review inspect <campaign> --file evidence/request.http --url https://app.example.test/`
  performs conservative HTTP/1 framing lint on a local capture. `http-review
  show|status|verify` inspect the hash-bound local journal. No bytes are sent or
  forwarded. Rejection means the capture fails this validator's strict subset,
  not that any deployed parser accepts it or disagrees with another parser.
  HTTP/2, chunk extensions/trailers and connection traces remain unsupported.
  The loopback JSON review-gate test submits captured bytes as **data**, not as
  malformed network traffic, and cannot prove a desync effect. See
  `docs/offline-cache-http-review.md` for supported cases and limits.
- `http-smuggling` routes here only when an endpoint has the explicit boolean
  asset attribute `http_smuggling_review=true`, designated by an operator.
  This produces an untested review row, not authorization or evidence of a bug.
  There is no automatic CDN/H2 seeding or topology collector.
- `python3 -m recon send` is an ordinary scoped HTTP client, **not a byte-exact
  smuggling transport**. Native request capture retains header names, not their
  values/order/duplicates; response maps collapse duplicates. Burp/HAR normalized
  projections cannot reconstruct original framing or connection identity.
  A HAR `connection` label or a proxy entry ID is not an upstream socket trace.
- There is no smuggling CLI, config grant, parser-differential engine, raw-socket
  executor or automatic finding promotion. Do not invent one or route around the
  scoped client's Host/proxy/GET-body restrictions.

## Evidence decision

| Evidence | Honest conclusion |
|---|---|
| Server banner, H2 negotiated at the edge, one slow response | Surface/hypothesis; upstream protocol and cause unknown |
| Repeated anomaly, no shared-connection trace or fixed control | Observed anomaly; desync inconclusive |
| Complete capture and correlated per-hop parsing/connection evidence disagree | Attributed boundary disagreement for that exact case |
| Fresh owned B receives A's marker without sending it; fixed control does not; normal positive control works | Owned effect, subject to attribution, isolation and replay review |
| Negative control reproduces the alleged effect | Reject that causal claim; keep artifacts and explain the confounder |
| Only lab evidence or browser delivery not demonstrated | Lab-only or conditional; not a target impact claim |

The negative control is mandatory before confirmation: the alleged exploit
assertion must fail there while the benign positive control still works. Treat
cache hits, retries, application reflection, load-balancer routing and client
normalization as alternatives to eliminate, not additional proof of smuggling.

## Handoffs and reporting

Use `hunt-access-control`/`hunt-idor` for a demonstrated authorization consequence,
`hunt-xss` for actual script execution and the existing cache evidence workflow
for an independently attributed cache effect. A smuggling lead does not prove
any of those downstream effects. Keep one root cause with sourced chain edges.

Apply `recon/prompts/validator.md` before confirmation or reporting: exact replay,
distinct failing negative control, realistic preconditions and minimum owned
impact proof. Generic replay/control hashes alone do not certify parser causality.
Do not promote a finding automatically or award severity from a class name.

## Hard limits and stop/resume

Stop at 429, challenge/lockout, unexpected 5xx, unowned traffic, wrong destination,
cross-user effect, unknown residual state, lost capture or any cap. Pause the
exercise and notify the owner. A local client close does not prove the backend
pool is clean. Resume only after the owner verifies pool reset/expiry, relevant
cache cleanup and a clean baseline, reconciles counts and approves resumption.

Read [sources](references/sources.md) for standards, research and remediation.

Disclosed-report precedent for this class — scale, highest-bounty disclosures and
corpus queries: [references/corpus.md](references/corpus.md). Precedent, not evidence:
a disclosed report shows a bug was accepted somewhere, never that this target has it.
