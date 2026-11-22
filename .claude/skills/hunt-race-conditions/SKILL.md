---
name: hunt-race-conditions
description: "Investigate race-conditions coverage on authorized BugVault campaigns with a shared owned business invariant and exact writer/resource graph. Use RC-01..RC-21 offline scenarios, serial controls, source-qualified member receipts, bounded run denominators and operator-attested Burp/Turbo gate imports; never infer a race from two successful responses or parallel tasks. Load for any schedule-dependent effect or race coverage row."
license: "MIT; original BugVault workflow. External research concepts are referenced, not copied."
metadata:
  implementation: "recon/invariants.py and recon/race.py; offline evidence, no synchronized sender"
  reviewed: "2026-11-16"
---

# Hunt: schedule-dependent invariant effects

An owned resource, safe
consequence, reviewed methods/budget and suitable channel are mandatory. The only C-P import lane is
**operator-run** under a standing program plan: the operator, not the agent, fires
the named gate. Agent-driven synchronization remains M6-blocked; ordinary Burp
MCP tabs, Intruder preparation and concurrent browser fetches are not a gate.

1. Use `python3 -m recon race sync <campaign>` for offline signals and
   sequence-first logic survivors; `race profile <campaign> --host <host>` gives
   ranked source-labelled tells, not a demonstrated race. Read [cases](references/cases.md)
   and [schedules](references/schedules.md). Declare a schema-1 invariant through
   `logic declare` first, then a 2–8 exact-writer scenario with
   `python3 -m recon race declare <campaign> --file <scenario.json>`.
2. `python3 -m recon race plan <campaign>` shows exact context/case readiness.
   Prepare A→B and B→A where order matters, disjoint-resource/fixed controls,
   a shared-resource schedule and fresh-fixture replay; if sequential already
   violates, route the primary claim to `hunt-business-logic`. Every writer
   explicitly touches one owned/shared resource. See [confounders](references/confounders.md).
3. In a permitted M5a operator exercise only, import installed tool/version/engine,
   protocol, gate, operator, send/retry/connection counts, imported member refs and
   attestation artifact via `python3 -m recon race attest <campaign> --file
   <attestation.json>`. This charges **declared** external attempts once but does
   not intercept Burp, attest application overlap or grant a target send.
4. `python3 -m recon race record <campaign> --file <run.json>` appends sourced
   per-member observations, concurrent `parallelism/attempts/successes` and
   separate invariant versus causality verdicts. Constraint/serialization error
   under a schedule is `observed` **window evidence**, never a policy breach by
   itself. Current status leaves the return-to-contract *threshold* unset:
   point counts without matched schedule offsets and owner trace cannot prove a
   window boundary. Do not use a success-rate target to decide how many runs to send.
   `race status` shows blockers/denominators; `race verify` returns exit 2 for
   invalid artifacts/attestations. Neither promotes a finding.

Two 200s with one authoritative effect, a reversed response order, UI/cache lag,
or a legitimate idempotent replay is not a proven race. An unknown member outcome
remains charged and potentially committed; reconcile the owned oracle before any
retry. Keep the operator's external-declared attempt separate from imported Burp
captures: neither can be relabelled `target-http`/native. A chain hint without
shared invariant/resource/root lineage is not T4. If an upload finalize/processing
question is primary, hand its lifecycle to `hunt-file-upload` first.

RC-21 uses two separately owned A/V contexts and one owned one-time artifact; the
authentication/ATO owner proves a downstream session effect, not this ledger.
Hand off object/field policy to `hunt-idor`/`hunt-access-control`, browser
cross-site delivery to `hunt-csrf`, and value/sequence-only faults to
`hunt-business-logic`. Read [evidence](references/evidence.md) and
[sources](references/sources.md) before a claim.

Disclosed-report precedent for this class — scale, highest-bounty disclosures and
corpus queries: [references/corpus.md](references/corpus.md). Precedent, not evidence:
a disclosed report shows a bug was accepted somewhere, never that this target has it.
