---
name: hunt-business-logic
description: "Investigate business-logic coverage on authorized BugVault campaigns: owned workflow invariants, sequence/value contrasts, bounded anomaly-first BL-00 observations and BL-01..BL-18 cases, terminal-impact evidence, and offline logic ledger. Load for every business-logic row or an unexplained wrong value, entitlement, limit or state transition. Race scheduling is owned by hunt-race-conditions."
license: "MIT; original BugVault workflow. External research concepts are referenced, not copied."
metadata:
  implementation: "recon/invariants.py and recon/logic.py; offline evidence, no target executor"
  reviewed: "2026-11-16"
---

# Hunt: business invariants

live actions require exact scope, method and an approved dedicated browser/Burp or campaign-approved channel.
Offline commands are not an alternate live transport.

1. `python3 -m recon logic sync <campaign>` lists candidate captures; a route name
   does not establish a rule. Read [invariants](references/invariants.md) and
   [cases](references/cases.md). Declare schema-1 owned workflow/operations/resources,
   owner-backed or `inferred-observed` policy and an authoritative oracle with
   `python3 -m recon logic declare <campaign> --file <declaration.json>`.
2. `python3 -m recon logic probe <campaign> --workflow <key>` makes **value-free**
   cards (maximum 50); `logic observe --file` stores a bounded, redacted differential
   as T0/T1 **unadjudicated**, even when owner policy is unknown. `logic close`
   closes a dead lead with a reason; it cannot report a vulnerability.
3. `python3 -m recon logic plan <campaign>` shows exact context/invariant readiness.
   Prefer a valid sequence/value path, one owned variant, a named refusing control
   (`unknown` is honest) and independent authoritative state. A survived named
   control on a concurrency-relevant invariant opens a linked race **candidate**;
   it never closes this logic case. Read [evidence](references/evidence.md).
4. After an authorized operator exercise, import redacted, campaign-local artifacts
   and source-qualified receipts via `python3 -m recon logic record <campaign> --file
   <event.json>`. `observed` is a typed comparison, not a finding. `logic status`
   and `logic verify` expose stale/invalid evidence; verify returns exit 2 on
   invalid integrity. `logic cleanup` and `logic resume` only record receipts and
   gate **ledger readiness**, not Burp or native network dispatch.
5. T2/T3 need one owned disposable field/value change or one owned sensitive field
   with independent readback, redaction and cleanup. T4 needs the target class's own
   impact proof and shared lineage. A T0/T1 lead is not reportable; human validator
   checks the declared contract, negative control, replay, gain, blast radius and fix.

Judge the **declared policy** against the settled owner oracle, not 200 responses,
cached UI state or a guessed overdraft/role rule. An inferred-only differential is
not validator-ready; a valid same-intent retry with one effect is not a duplicate
benefit. If both serial and competing schedules violate the rule, keep business
logic primary and race causality unresolved. Never follow an out-of-scope payment
redirect to prove a synthetic value discrepancy.

Hand off object swaps to `hunt-idor`, function/field access to
`hunt-access-control`, browser cross-site delivery to `hunt-csrf`, account/session
effects to `hunt-ato` and schedule dependence to `hunt-race-conditions`. Source
and license distinctions: [sources](references/sources.md).

Disclosed-report precedent for this class — scale, highest-bounty disclosures and
corpus queries: [references/corpus.md](references/corpus.md). Precedent, not evidence:
a disclosed report shows a bug was accepted somewhere, never that this target has it.
