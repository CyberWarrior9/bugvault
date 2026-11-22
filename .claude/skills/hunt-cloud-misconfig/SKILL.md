---
name: hunt-cloud-misconfig
description: "Cloud-misconfiguration investigation for authorized BugVault campaigns. Load for cloud-misconfiguration coverage, storage or signed-delivery references, cloud identity/trust/federation, RUM/Cognito, workload metadata, deployment consumers, or candidate cloud credentials. Use recon cloud to map source-qualified leads and offline evidence; separate ownership, exact operation, principal/session, policy, observed effect and independently controlled impact. A public identifier, scanner verdict or recorded canary does not confirm a cloud vulnerability. Never treat the ledger as a cloud executor or a traffic grant."
license: "MIT; original BugVault workflow with cited external concepts, no copied code."
metadata:
  implementation: "recon/cloud_refs.py and recon/cloud.py; offline partial M1-M3 plus R5 hostname proposals"
  reviewed: "2026-11-16"
---

# Cloud misconfiguration: boundary to controlled effect

Read the canonical `plans/cloud-misconfiguration.md` for the complete
R1–R8 proposal and `reports/Cloud misconfiguration hunting plan.md` for the
four-source research and provider matrix. Those documents are proposals, not
implemented grants or provider certification. Current tools support **offline
M1–M3 only**; use the dedicated visible browser/Burp default for separately
approved target interactions, or `python3 -m recon send` if a standing plan
explicitly permits native HTTP. Neither is a cloud SDK, account scanner or
permission oracle. This conversation has no connected dedicated browser.

## Workflow

1. **Bind the lead.** Existing stored in-scope responses:
   `python3 -m recon cloud sync <campaign>`. For an operator-supplied local text
   export, place it inside the campaign folder, then
   `python3 -m recon cloud import <campaign> --file evidence/refs.txt`.
   Both are offline. They parse S3/GCS/Blob references, ARNs, Azure IDs,
   RUM/Cognito/Firebase public identifiers with source hashes and selectors.
   The extractor neither guesses names, fetches the URL nor validates a secret.
   A separate **offline** `python3 -m recon cloud generate <campaign> --file
   evidence/generation.json` proposes hostname candidates on an explicitly
   in-scope program wildcard under a reviewed discovery label and loud mode.
   It never probes, claims or queues shared-provider names; supplied words
   are not independently verified as target-derived.
2. **Triage without inferring impact.** `python3 -m recon cloud plan <campaign>`
   and `python3 -m recon cloud show <campaign> --reference N` show a bounded
   priority queue. Priority is **not** severity, ownership or testedness. A
   signed URL is delegated access, not anonymous. A Firebase browser key,
   RUM monitor ID or AWS account number is not a credential by itself.
3. **Map the exact boundary.** Name provider/partition/account/tenant/project,
   principal *and session*, action/method, resource/version, expected policy,
   working owner baseline, lower-trust context and defeating controls.
   See [case cards](references/cases.md). Anonymous, signed, low-privilege and
   derived identities are separate contexts; a denied list is not a denied
   known-object read. A provider suffix or generated name is not ownership.
4. **Choose the smallest permitted consequence.** Consider read, write,
   persistence, actual consumer and cross-scope chains, not a fixed depth cap.
   Read [evidence and readiness](references/evidence.md) first. Operator-owned
   canaries and distinct negative controls let you demonstrate high impact
   without accessing real users. No target destruction, hidden credential use,
   account claims or collector/spray dispatch follows from a lead.
5. **Record only performed observations.** A campaign-local event JSON with
   `schema:1`, `reference`, `case:CM-00..CM-18`, `state`, `channel`,
   `operation:{principal,action,resource_id,method}`, and labelled artifact
   paths goes to `python3 -m recon cloud record <campaign> --file evidence/event.json`.
   Consult the installed validator for accepted keys. Live-labelled evidence
   requires the reviewed rules, appropriate cloud evidence label, method,
   approved URL, request receipts and positive declared budget **in addition to**
   actual program approval and execution-path policy. `record` never sends.
   `canary-proved` checks distinct role hashes and markers; it does **not**
   certify semantics, reportability or a finding. `verify` detects altered
   inputs, receipts and scope/policy staleness; it does not validate IAM.

## Current boundaries and handoffs

- `recon cloud` currently implements **import/generate/sync/plan/show/record/status/verify**.
  `generate` is an offline hostname proposal only. It does **not** implement
  provider-namespace discovery, `declare`, `graph`, `handoff`,
  `cleanup`, `resume`, SDK mediation, Prowler import, credential exchange or a
  provider lab. The plan's M2.5 and full M3.5/R5–R8 acceptance are **open**.
  Do not assert they passed.
- A scope wildcard for an application host itself authorize probing
  globally shared storage namespaces, guessed provider names or third-party
  tenants.
- Always use a token-looking value or pivot an identity based only on a discovery
  receipt. One approved chain can cover multiple declared hops, but each exact new identity, resource, action, budget and stop applies.
  There is **no** implemented chain-grant executor or cloud SDK here.
- An R7 impact envelope is a **future proposal**, not an authorization to delete,
  run code, create billable resources or exfiltrate target data. 
- Route actual fetch causality to `hunt-ssrf`, attacker-controlled artifact
  intake to `hunt-file-upload`, object-specific policy to `hunt-idor`,
  host claiming to `hunt-takeover`, and login/account control to `hunt-ato`.
  Do not borrow a sibling finding as proof. Require replay, independent
  negative control and the existing validator/reportability review.

If policy, tool, ownership or observer is missing, preserve a **blocked or
inconclusive** case and list the exact missing term; do not switch clients,
pretend an owner supplied an artifact, or mark a provider covered.

Disclosed-report precedent for this class — scale, highest-bounty disclosures and
corpus queries: [references/corpus.md](references/corpus.md). Precedent, not evidence:
a disclosed report shows a bug was accepted somewhere, never that this target has it.
