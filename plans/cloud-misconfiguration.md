# Cloud misconfiguration: engineering and hunt contract

**Status: partial implementation checkpoint, 2026-11-16.** The R1–R8 rounds remain a proposed target architecture, not an executed campaign. The installed slice is detailed below; no SDK adapter, live cloud test, provider certification or traffic grant exists. The [full cited report](../reports/Cloud%20misconfiguration%20hunting%20plan.md) remains the earlier research snapshot (42 provider-family rows, D0–D8+ and eight illustrative chains), not evidence that those cases were implemented or tested.

### Implementation checkpoint — installed versus open

| Area | Implemented now | Still open |
|---|---|---|
| **M1 / A1 / R4 partial** | `recon/cloud_refs.py` parses bounded S3/GCS/Blob references, AWS ARNs, Azure resource IDs, RUM/Cognito/Firebase public IDs. Native IDs, scope fragments, source span/hash, signed-context indicator and deterministic priority are recorded. `recon cloud import/sync/plan/show` reads only campaign-local text or paged stored in-scope response bodies; `verify` rechecks extracted selectors. | Full JS/HAR/APK/CT value-preserving adapters, complete provider-native alias/version semantics, cross-scope and secret-shaped triage, multi-cloud inventory graph and visibility denominator. |
| **M2 partial / A2 / A4** | `recon cloud record/status/verify` accepts exact reference-bound operation receipts with labelled campaign-local artifacts, checked canary markers, current scope/policy snapshot, method/grant and declared-budget gates for live-labelled receipts. Reports label these leads as conditional. | Independent provider-policy evaluator, generalized tri-fact lifecycle, typed resource-only finding anchors and validator integration, explicit cleanup/stop/resume accounting across all traffic channels. `canary-proved` is not semantic confirmation. |
| **Skill and tests** | `hunt-cloud-misconfig`, source/case/evidence guidance and three judgment cases are present. Unit/CLI/report tests use synthetic or stored-fixture data only. | Judgment cases have not been run with a clean isolated model baseline; no behavioral skill-effect claim. |
| **R5 partial / M3.5** | `recon cloud generate` records bounded **offline hostname proposals only** from operator-supplied words, under a reviewed discovery label, loud mode and an explicit in-scope program wildcard; it refuses known shared provider domains and never probes/claims/queues. | No verified target-derived dictionary provenance, exhaustive shared-provider classification, live discovery runner or provider-namespace ownership/permission model. A website wildcard cannot authorize bucket-name or identity probing. |
| **R1–R4/R6–R8 and M2.5+** | The existing scoped `recon send` remains the only built-in native HTTP path; this cloud ledger dispatches nothing. | No owned cloud account B, browser-control connection, provider cloud executor, credential validation/pivot, R7 real-effect exercise, cross-process Burp/SDK budget mediation, Prowler adapter, AWS/Azure/GCP provider pilot or cleanup/cost certification. |

For the installed commands and accepted evidence labels, inspect `recon/cloud.py` and the skill rather than treating this design contract's future schema as the current wire format. Recorded outputs cannot certify real cloud IAM, provider identity or reportability. Subsequent milestones require a written authorized campaign, exact provider-resource scope, owned canaries/principals, approved operation/channel and a connected observer.

**Verification against acceptance gates (Python 3.15.2, 2026-11-16):**

| Gate | Actual result | Still open |
|---|---|---|
| Partial A1/A2/R4/R5 offline checks | `tests/test_recon_cloud.py` and `tests/test_recon_cloud_lab.py`: **20 passed**. They cover extraction/redaction, archive decay, paged stored-response sync, source/selector/receipt integrity and staleness, scope/label/declared-budget checks, hostname proposal refusal, CLI smoke, corrupt-event detection and an owned local storage-shaped canary. | The full Gate A matrix below: cross-provider policy semantics, typed cloud graph/migrations, complete context/coverage, stop/cost enforcement, provider namespace provenance/traffic controls. |
| Partial B-local | One owned-loopback fixture demonstrates a write, readback/replay, denied sibling control and cleanup; **not** an actual cloud provider or a complete vulnerable/fixed/legitimate-control matrix. | Remaining B-local scenarios, owned account-B full-chain rehearsal and every B-cloud pilot. |
| Gate C | Three judgment case files exist. **No clean isolated skill-vs-baseline model run** took place. | Behavioral evaluation, provider semantic review and critical-error acceptance. |
| Regression | `python3 -m unittest discover -s tests -q`: **694 tests run, 2 skipped, 0 failures**. ResourceWarnings and expected negative-case CLI error lines appeared; focused changed tracked paths pass `git diff --check`. | Skips/warnings not resolved here; global diff check still flags unrelated CRLF CSV whitespace. No live provider or authorized target acceptance. |

## Outcome and first priorities

Build a hunt workflow around **misconfiguration → boundary failure → controlled effect**. Its exact unit is `provider / scope / principal-session / operation / resource-version / context / policy-version`, not an endpoint or failed-check title. Follow new evidenced, authorized capabilities recursively; there is no arbitrary chain-depth cap. Do not require every confidentiality proof to become execution or mark a provider covered after a finite number of attempts. The **R1–R4 and R5–R8 revisions below** make the same workflow execution-first, mutation-first, owner-independent, triage-driven, discovery-capable, pivot-continuous and impact-real inside the unchanged mandatory envelope — the attacker's objective function executed through authorized means.

### Four adopted additions and revised delivery order

Following comparison with `/tmp/plan_cloud_misconfig.md`, adopt these **four** additions. The installed subset is stated above; remaining parts are not implemented. Keep the original exact-operation identity, policy, proof, privacy, accounting and cleanup requirements throughout.

1. **A1 / P1 — Shared cloud-reference extractor first.** Make a pure, source-qualified `cloud_references()` parser the first reusable deliverable for cloud, JS/API mapping and takeover consumers. Extract concrete identifiers before building a broad inventory graph or scanner adapter.
2. **A2 / P2 — Anonymous-access vertical slice before Prowler.** Deliver reference → ownership/context → exact operation → controlled observation → evidence-backed disposition, with the minimum typed resource/context/evidence model required for correctness. Do not wait for a complete multi-cloud graph, IAM evaluator or scanner integration.
3. **A3 / P3 — Explicit RUM/browser-bootstrap investigation card.** Add CloudWatch RUM, browser SDK bootstrap and related Cognito/identity references as a named candidate surface. Research and validate its prerequisites before advertising a supported provider technique; public monitor IDs and intended telemetry ingestion are not vulnerabilities.
4. **A4 / P4 — Content-sensitive impact classification and next-proof routing.** Add content kind, intended publicness, confidence and consumer context to read observations and handoffs. Use them to choose the next exact proof, not to infer severity or validate discovered credentials automatically.

Implement A4's minimal assessment fields alongside P2, and A3's static extraction hooks alongside P1; the numbering expresses priorities, not a requirement to defer those shared fields. Expand the typed identity/policy/dependency graph and add **one pinned Prowler adapter later**, after the anonymous slice has acceptance evidence. Preserve scanner verdict/lifecycle/severity/visibility separately and obtain an actual owned/redacted export sample before promising format compatibility. **R1 below supersedes "no cloud executor"**: an owned-lab execution surface and an operator-initiated probe channel become first-class planned deliverables at M2.5. Still no scanner dispatch, ambient-credential SDK executor or automatic probing follows from this plan.

### A1 — Shared extraction contract

Proposed pure API: `cloud_references(text, *, source_ref, media_type) -> reference records`. Reuse it from stored JS/lazy chunks/maps, HTML, API/error responses, APK-derived text, upload destinations and normalized captured DNS/CT references. This parses existing artifacts; the parser itself does not fetch a URL, resolve a name, generate names or validate credentials — generation and validation are separate granted components (R5, R6) that consume its output.

Each reference records `provider`, `resource_kind`, `native_identifier` or unresolved candidate, optional known partition/account/tenant/project/region/version, source record and source hash, exact selector/span, current-versus-archived context, extraction confidence, ownership state and explicit gaps. Unknown scope remains unknown. Types include storage/object references, function/API URLs, ARNs, registry/queue references, Cognito pools, Firebase configuration, RUM monitors and signed-delivery endpoints. A provider suffix or account ID without a concrete resource remains an identification hint, not a resource ownership assertion. R4 adds offline deterministic triage fields to every extracted reference — writability, identity-linkage, secret-shape, consumer-executable and cross-scope hints with staleness decay and a composite `probe_priority` — so a ranked queue, not a hand-picked lead, drives case selection.

Normalize supported aliases without merging different accounts, tenants, projects, partitions or versions. Remove signed URL credentials, tokens and secret values from model-facing records; preserve only a protected source reference and value-free indicators where needed. Extraction of a credential-looking value produces a disclosure handoff, not a live validation request. Name permutation is no longer globally forbidden: under the R5 discovery lane a scope-covered namespace pattern may seed budgeted candidate generation, while an observed naming pattern alone still establishes neither target ownership nor permission to probe a foreign namespace — candidates stay ownership-ambiguous until bound.

Acceptance: source/span/hash round trip; supported AWS/Azure/GCP identifier fixtures; aliases and cross-scope collisions; incomplete and archived inputs; RUM/Cognito/Firebase public-identifier false positives; signed-URL redaction; malformed/ambiguous strings; and zero network, credential validation or target-queue side effects (the parser itself; R5/R6 components carry their own grants and acceptance).

### A2 — Anonymous-access first release

Use only an attributed, scoped resource and a known benign object/operation or owner-seeded canary. Bind intended access and a working legitimate baseline, then compare the exact anonymous context without ambient SDK credentials. A signed URL, SAS, cookie or bearer-bearing request is a distinct credentialed/delegated context, not anonymous access.

Treat existence, listing, known-object read, write and service invocation as independent cases; **listing is not a universal first step**. If a harmless exact object is already known, its permitted read contrast can be the smaller useful proof. Denied listing does not establish object privacy. Nor is read the universal first step: under R2, when a writable or cross-account boundary is plausibly in scope and the operation grant exists, the mutation or terminator case is probed first and read becomes the fallback. Status/header/error patterns produce qualified observations; they do not alone prove existence, authorization failure, readability or writability.

First-release flow: reference → ownership and intended boundary → exact operation/context → owner and low-context baselines → approved operator observation or clearly labelled owned fixture → replay/independent negative control/readback → content assessment → disposition and next-proof handoff. An unsigned write needs a separate operation grant, a disposable key, before/after independent readback and cleanup; a before-image is not its independent negative control. Initial software support analyzes stored captures and records supplied evidence; from M2.5, operator-initiated unsigned probes run only through the R1 approved channel under their own method/operation grants, budget accounting, negative control, readback and cleanup — never automatic dispatch, and never a new transport. Under an R7 impact envelope, read and write proofs may use the envelope's real-effect classes instead of synthetic markers; caps, readback and cleanup receipts still apply.

Acceptance: an end-to-end known-object storage fixture and matched private/fixed control, plus independent list/read/write/service and anonymous-versus-signed-context tests. Use provider-labelled S3/GCS/Blob parsing fixtures without claiming their local behavior certifies real provider IAM. Record incomplete capture, ambiguous provider responses and missing context as unknown/inconclusive. Advertise only provider operations whose semantics and fixtures were actually reviewed. Prowler support is not a prerequisite for this release.

### A3 — RUM and browser-bootstrap candidate card

Initial signals are stored RUM SDK initialization, app-monitor IDs, region, Cognito identity configuration, endpoint references and related identity/role information supplied by the owner. The proposed path is browser configuration → monitor/identity binding → actual permitted role/session → effective operation → unintended owned-resource consequence. Do not assume every RUM deployment has the same identity flow or that every captured identifier maps to a reusable role.

The comparison plan supplies a **lead**, not verified current exploitation semantics. Before implementing provider-specific checks, review current official RUM/Cognito documentation, the exact deployment configuration, intended public ingestion and any identity/trust constraints. This is future source validation, not an extra researched source or a finding added to the four-source report. Do not repeat unverified “2024–2026 weaponization” claims as established facts.

Expected monitor visibility, public IDs, intended telemetry submission or an expected temporary identity are not sufficient impact. Only separately approved tests on an owned monitor/test identity may establish an unintended permission or consumer effect. Use benign uniquely marked events and constrained canary resources with legitimate and expected-denied controls; no event flooding, production telemetry pollution, billing-impact exercise or exported credentials. Missing identity/permission evidence keeps downstream edges conditional. Add explicit fixtures for intended-public configuration and telemetry-only permissions versus an independently proven canary permission excess.

### A4 — Content-aware impact and recursive handoff

For a read observation, store a separate `content_assessment`: `content_class` (`public-asset`, `source`, `config`, `backup`, `pii`, `credential-looking`, `synthetic`, `unknown`), `intended_publicness` (`public-intended`, `private`, `unknown`), `confidence` (`hint`, `source-supported`, `owner-bound`, `controlled`), evidence refs/selectors and known consumer/resource refs. A content label never substitutes for a demonstrated access boundary. `credential-looking` is deliberately not a claim of credential validity.

Use only permitted, minimized evidence, synthetic marker content or an owner's redacted classification; do not retrieve additional sensitive material just to populate a label. Keep raw credentials and personal data out of model-facing packets. `unknown` remains a valid observation with a reason and an inconclusive impact assessment; do not reject, erase or invent a classification merely to close a case.

Route public-intended assets without another violated boundary to a non-finding/expected-use disposition; source/config references to ownership and identity/scope analysis; backups or purported sensitive content to an exact synthetic disclosure proof and intent review; credential-looking material to a separately authorized identity/purpose/scope task; and writable artifacts to the actual consumer/version/trigger proof. Each resulting resource or identity edge gets fresh context, permission and controls under the existing recursive depth model. Acceptance contrasts public marketing assets with intended-private synthetic source/config/backup content, unverified credential-shaped strings, unconsumed writes, unknown labels and independently attributable consumer effects. An R7 envelope can upgrade a proof's class from synthetic marker to real effect; content assessment still governs sensitivity, minimization and routing either way.

## Red-team revision (2026-11-16): execution-first, mutation-first, owner-independent

Modeling the plan against a black-hat operator exposed four methodological blockers, none of which is the mandatory envelope itself. Programs rate demonstrated capability with controlled proof, so authorization, no-production-destruction and budget rules cost nothing in finding quality; being offline, read-first, owner-dependent and one-lead-at-a-time costs everything. R1–R4 remove those four blockers with the envelope unchanged.

| Blocker | Where it lived | Revision |
|---|---|---|
| Zero execution until M6; offline analysis can never resolve D5/D6 effective-permission and derived-identity facts | A2 flow, live-connector section, M6 | **R1** — owned adversary account plus approved probe channel at M2.5 |
| Read-first ordering; mutation a gated exception; no persistence, audit-invisibility or credential-validation lanes | A2 cases, hunt lanes, CM taxonomy | **R2** — attacker-objective tier and owned-lab full-chain rehearsal |
| Confirmation routes through owner exports/samples; unresponsive owners strand bugs at `hint` | E/L/O table, H2 lane, M5 | **R3** — owner-independent confirmation ladder; Prowler demoted to worklist source |
| One hand-picked lead; no ranking story for thousands of A1 references | Day-one checklist | **R4** — deterministic harvest-scale triage queue |

### R1 — Execution-first path: owned adversary account and approved probe channel

The R1 proposal would add two separately sanctioned execution surfaces at M2.5 **if provisioned and approved**. Neither is supplied by the installed cloud ledger; "missing tools" remains a blocker in this session:

1. **Owned adversary account B** — an operator-provisioned lowest-tier account with no production trusts, data or users. It is a proposed rehearsal context for approved owned resources. A target trust or policy admitting B would establish an access observation, **not necessarily a boundary failure**: intended trust, ownership, actual use and written scope still need independent evidence. No account B has been provisioned by this implementation.
2. **Approved probe channel** — operator-initiated, grant-gated, budgeted requests against in-scope targets through existing paths only: the dedicated browser/Burp setup and `recon send` with explicit method grants. No new transport, no SDK ambient credentials, no automatic dispatch, nothing outside written scope. Mutation probes additionally need the R2 operation grants.

Where provider API use is separately approved and connected, exact identity and one-action contrasts can complement policy analysis. A provider response proves at most its actual operation under that principal/session and context; it cannot certify general effective permissions. Every probe remains an exact-operation event with accounting, control, readback and cleanup.

### R2 — Attacker-objective tier: mutation, persistence, durability, audit invisibility

Mutation and persistence can be high-impact cloud findings; their importance does not imply every cloud critical is a mutation. A proposed cross-cutting `objective_tier` orders ready cases alongside confidentiality, without replacing evidence or severity review. The CM families are unchanged.

| Tier | Attacker objective | Smallest target-side proof |
|---|---|---|
| `read` | leverage/exfiltration capability | existing known-object synthetic read |
| `mutate` | policy/trust modification, identity or credential creation, consumer-code injection | marker write, independent readback, one-edge fixed control |
| `persist` | access survives key rotation, revocation or remediation of the initial vector | renewed canary access after rotation on disposable resources |
| `audit-evade` | the successful action is unlogged, or logging is disableable | log-gap observation; never disabling target logging |
| `destroy-assess` | versioning/backup/MFA-delete bypass enabling mass delete or ransomware | reasoned and owned-lab-proven only; on targets a marker write plus version-list readback, or canary-object delete + version restore under an R7 envelope — never deletion of non-canary production data |

At equal readiness, the proposed workflow prioritizes the highest independently approved tier; read-first is not a universal rule. The full chain — read → escalate → mutate → persist → destroy — **would be rehearsed** in an owned account B, not asserted as a completed test. Destruction capability is never performed on production targets; any synthetic equivalent still needs semantic/reportability review.

**Credential-validation lane.** A live-looking discovered credential no longer waits forever in a disclosure handoff. Where program rules explicitly permit it, a grant-gated protocol verifies identity only — one get-caller-identity-class call, zero data access — recording validity and binding separately from any use, then stops. Without that explicit grant the disclosure handoff stands; nothing here authorizes data-plane use of discovered credentials. R6 generalizes this minimum into the full chain grant; absent any grant, this lane is the ceiling.

### R3 — Owner-independent confirmation ladder

Unresponsive owners must not strand real findings at `hint`/`source-supported`. For external contexts, confirmation terminates on any **owner-absent proof**:

1. Canary-object write to a target-writable resource plus independent readback, from the anonymous or supplied-low context.
2. An owner-staged or independently evidenced intended-private synthetic object read against a known-object contrast. Content shape alone cannot establish intended privacy; absent an owner label or equivalent independent policy evidence, preserve `intended_publicness=unknown`.
3. Cross-account access from owned account B into a target-granted trust or resource policy.

Owner artifacts — policies, exports, Prowler samples, intent labels — now enhance confidence and intent classification instead of gating confirmation. Scope inclusion still derives only from written program rules, never DNS/IP or guesswork, and the reportability validator still decides promotion. M5 Prowler support is demoted from a confirmation dependency to a worklist and visibility source.

### R4 — Harvest-scale reference triage

A1 across stored JS, HTML, maps, HAR and APK artifacts will produce thousands of references; a hand-picked single lead cannot rank them. Each reference receives offline deterministic triage fields: `writability_hints` (upload endpoints, mutable resource kinds), `identity_linked` (roles, pools, service accounts, federation references), `secret_shaped` (credential-shaped material awaiting any R2 validation grant), `consumer_executable` (functions, build/deploy artifacts, packages), `cross_scope` (foreign-account/tenant references), decayed by staleness into a composite `probe_priority`. The ranked queue feeds the day-one worksheet and case selection per campaign window. Triage is auditable and reproducible; it orders probes and never fabricates ownership, permission or namespaces.

## Red-team revision round 2 (2026-11-16): active discovery, chain pivot, real impact

R1–R4 made the workflow execution-first, mutation-first, owner-independent and triage-driven. Round 2 removes the three remaining methodology blockers between this plan and critical-rate findings, plus two sequencing/budget relaxations. Each is a **named written-grant action class**: the authority source stays the program's written scope; what disappears is this plan's own default prohibition of the activities that produce most cloud criticals.

| Blocker | Where it lived | Revision |
|---|---|---|
| Name/namespace generation forbidden outright — most cloud criticals sit at names the owner never mentioned | A1 no-generation rule, day-one checklist | **R5** — authorized active-discovery lane |
| Validation capped at one identity call and every pivot needs a fresh approval — "secret found" (low) versus "account takeover" (critical) is exactly validation + pivot | A1 disclosure handoff, credential refs, readiness terms | **R6** — chain-grant validation and identity pivot |
| Synthetic-marker-only proofs truncate impact into "could have been read"; criticals are demonstrated effects | A4, A2 flow, B-cloud serial approvals | **R7** — pre-approved impact envelope |
| AWS-only sequencing stalls Azure/GCP; default attempt caps throttle lawful enumeration | Hunt-lane note, M7, accounting limits | **R8** — parallel provider track and enumeration-burst budgets |

### R5 — Authorized active-discovery lane (candidate generation in)

Live generation-and-probe is proposed as a **scoped, rate-bounded, pre-approved action class**, not implemented in this slice. The installed offline hostname generator is narrower (see checkpoint). An explicit written provider-namespace or hostname grant must cover the *actual probed surface*; an application wildcard such as `*.target.com` does not by itself authorize queries to globally shared bucket or identity namespaces. A granted namespace pattern plus target-derived tokens may later be expanded into candidates only when the run plan declares the dictionary, endpoints, ownership safeguards, volume and shared budget. Generating a string offline and probing its provider endpoint are separate operations.

Boundaries that keep it defensible:

- **Target-derived dictionaries, never keyspace.** Candidates come from scope-declared patterns and observed tokens; full-namespace brute force and credential spraying stay prohibited (unchanged absolute rule).
- **Candidates, not findings.** A generated name that resolves is ownership-ambiguous until bound by content, DNS linkage, certificate history or program confirmation. A coincidental foreign-tenant resource is a false positive and out of scope by definition — probing it further is a scope violation, not depth.
- **Rate/budget discipline.** Generation volume is pre-declared, counted in shared accounting, respects provider rate signals (429 → backoff) and never borrows another lane's budget.
- **Claim handoff.** A dangling reference whose resource is claimable routes to the existing hunt-takeover workflow; R5 generates and probes, it never claims.

A1's `cloud_references()` stays a pure parser; the generator is a separate deterministic component consuming A1 output plus scope-declared patterns, emitting candidate records with source, dictionary and confidence.

### R6 — Chain-grant credential validation and identity pivot

One standing **chain grant** (single written approval) replaces per-hop approvals for a discovered in-scope credential. Under it, the full critical path runs as one continuous proof: validation (GetCallerIdentity / token exchange / SA impersonation as provider-appropriate), bounded effective-permission enumeration from a declared API allowlist (attached-policy reads, authorization simulation, describe-class calls), and every derived identity/session becomes a **first-class hunting principal** with its own context, cases and events.

- The grant declares hop types, the enumeration allowlist, data-access limits (minimal necessary, marked), stop conditions (out-of-scope resource, real-user data, production mutation outside the R7 envelope) and revocation handling; it pre-declares the fresh edges explicitly rather than propagating silently.
- "No per-hop approval" never means software autonomy: execution stays operator-initiated through the R1 channel, and each hop is a recorded exact-operation event with accounting.
- Raw credential bytes never enter model-facing packets (unchanged); the ledger stores binding, validity and capability — never material.
- Without a chain grant, the R2 disclosure handoff stands unchanged. With one, SSRF → metadata → credential → pivot → terminal effect becomes one continuous proof instead of three disconnected low findings.

### R7 — Pre-approved impact envelope (real effects, not only synthetic markers)

A standing written **impact envelope** declares which real-effect proof classes are pre-approved per campaign, so impact claims stop being truncated into "could have" statements. On canary-owned resources always; on target resources where the envelope explicitly says so:

- **Overwrite/delete + restore of a canary object**, including versioned delete and version restore — real, reversible write-integrity effects.
- **Real code execution on a canary workload** — researcher-deployed function/container/job with command-output receipt.
- **Real confidentiality proof to an owned receiver** — researcher-staged synthetic sensitive content (or owner-designated canary data) retrieved through the permitted path end-to-end. Genuine production secrets are not automatically safe to extract or transmit, even as an excerpt or hash; request an explicit program-approved minimal proof or stop with a redacted owner-side validation handoff. **Real-user personal data is never exfiltrated.**
- **Resource creation with measurable billing impact** — bounded count/cost with receipts.

Caps, before/after readback, parallel branches under one envelope instead of serial one-fixture approvals, and cleanup receipts are retained — they are what make real-effect proofs defensible, not what blocks them. Synthetic markers remain the default where a program prefers them; the envelope upgrades the proof class without lowering the evidence bar. Destruction of non-canary production data stays outside every envelope, unchanged from R2.

### R8 — Parallel provider track and enumeration-burst budgets (honorable mentions)

- **Azure/GCP parity leaves the waiting room.** AWS remains the first fully certified lane, but Azure/GCP primary-source review, semantic cards and generic implementation proceed in parallel; only per-provider certification claims wait on their own primary review.
- **Enumeration-burst budgets.** Where written scope permits enumeration (including R5 generation), run plans may declare program-negotiated elevated attempt caps — shared-accounted, with provider rate-signal backoff — replacing the implicit assumption that low default caps fit enumeration work. Provider rate limits are facts to respect, not moral positions; scope and budget bound volume, not artificially low defaults.

### The first three hunt lanes and depth priority

| Priority | First useful boundary | Start in the context actually available | Next depth when independently ready |
|---|---|---|---|
| **H1 Storage and delegated delivery** | Intended-private object read, narrow owned write, or wrong-user/object/method/lifetime delegation | External known-object reference; supplied A/B users; owner canary optional — R3 canary write/readback or owned account-B terminator | Actual artifact consumer, origin/cache or cross-account canary, not speculative bulk data exposure |
| **H2 Effective identity/trust/federation** | A usable transition or canary authority absent from baseline A | Supplied low role; owner policy/trust/session exports optional under R3 external terminators | Service-mediated execution, wrong owned subject or owned account/tenant/project marker |
| **H3 Artifact → stronger consumer** | Bytes/configuration under A's control are actually consumed by B | Known public CI/artifact references plus owner deployment graph; disposable authorized build/job | Exact trigger/revision/runtime identity → B-only canary effect; recurse only on new capability |

AWS is first because the research includes primary AWS semantics. Under R8, Azure/GCP primary review, semantic cards and generic implementation proceed **in parallel**; only per-provider certification claims wait on their own primary-source validation. Technical expansion is not permission expansion. Branch readiness, not a universal read-only restriction, governs controlled writes/execution. Within every lane, R2's objective tier reorders candidate work — mutation and persistence boundaries outrank reads at equal readiness — and R3's account-B terminator can close H1/H2 with no owner artifact.

## Current baseline and fixed source boundary

The **pre-cloud research baseline** was **674 tests passed, zero skipped; 25 skills = 17 hunts + 8 guides**. It described the audited recon *at that time*, when it had no dedicated cloud skill, graph, Prowler adapter, provider semantic evaluator, SDK mediation or cloud executor. The current skill/offline CLI and regression status are in the implementation checkpoint above and handover below; no cloud SDK/real-provider tests have since been supplied. ([Handover](../Handover.md#2-current-status-honest); [local audit](../research_notes/Cloud%20misconfiguration%20hunting%20plan/bugvault-audit.md); [current capability catalog](../recon/catalog.py))

Exactly these **two GitHub resources and two websites** were researched, all accessed **2026-11-16**. Repository API/raw links are the same selected resources, not additional sources.

| Resource | Pin/license/role |
|---|---|
| [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler/commit/a5fd2d7eda90e9d59e0c4bfc0c74284b47529694) | Reviewed master **`a5fd2d7eda90e9d59e0c4bfc0c74284b47529694`**, **2026-11-16T17:10:36Z**; observed release **5.50.0**, **2026-11-16T16:29:19Z**, resolves instead to **`43de5f56739f45cd037282c6f763455002432daf`**. [Tag](https://api.github.com/repos/prowler-cloud/prowler/git/ref/tags/5.50.0). [Apache-2.0](https://github.com/prowler-cloud/prowler/blob/a5fd2d7eda90e9d59e0c4bfc0c74284b47529694/LICENSE). Observation/import reference; no copied checks, fixer or automatic secret validation. |
| [RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat/commit/63c65bd26edc6919499adfa20b176c450e35c33c) | **`63c65bd26edc6919499adfa20b176c450e35c33c`**, **2026-10-14T20:57:46Z**, checked-in **2.5.0**, not a latest release assertion. [Package](https://github.com/RhinoSecurityLabs/cloudgoat/blob/63c65bd26edc6919499adfa20b176c450e35c33c/pyproject.toml). [BSD 3-Clause](https://github.com/RhinoSecurityLabs/cloudgoat/blob/63c65bd26edc6919499adfa20b176c450e35c33c/LICENSE). Authored lab graphs, not production deployment or guaranteed reset/cleanup. |
| [cloud.hacktricks.wiki](https://cloud.hacktricks.wiki/en/pentesting-cloud/pentesting-cloud-methodology.html#basic-methodology) | Mutable secondary mechanism leads; no immutable revision/content archive. [Current content license not established](https://cloud.hacktricks.wiki/en/index.html#license--disclaimer). Original synthesis only, no payload/prose copying or inferred commercial-reuse permission. |
| [docs.aws.amazon.com](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) | Mutable primary AWS semantics. No blanket license assertion, no reproduced substantial prose/code. Specific uncertainties and current-schema caveats are preserved in the report. No Azure/GCP primary sources were reviewed. |

No external research is needed to implement this **offline generic contract**. Future provider-semantic/pricing/testing-policy review is a separately approved activity and does not silently change this four-resource research set. Existing takeover acceptance is local architectural background, not a fifth cloud research resource. Keep source notices and attribution if any future licensed incorporation is approved; this design imports none of the upstream code.

The later `/tmp/plan_cloud_misconfig.md` comparison is design-input provenance, not an independently verified online source or permission grant. This revision adopts A1–A4, not its stale 511-test baseline, assertion of a completed live SSRF/credential path, automatic list-first/permutation sequence or weaker status/header-only proof rules. The full cited report remains the original research snapshot; this canonical plan governs the revised build order and additions.

## Operating envelope and context contract

The report's [permission envelope](../reports/Cloud%20misconfiguration%20hunting%20plan.md#one-permission-envelope-enables-deep-work-without-inventing-authority) is normative: written scope/program/provider policy, owned principals/resources, action/method/channel approval, shared attempt/rate/time/resource/cost bounds, evidence privacy, stop/resume and cleanup. It interprets the requested depth without removing mandatory controls. Do not repeat exception requests for already approved reversible actions, but do not treat an evidence-recording grant as traffic permission. Preserve [scope-policy](../.claude/skills/scope-policy/SKILL.md), the dedicated browser/Burp default, `recon send` for approved native HTTP, current [Burp limits](../.claude/skills/scope-policy/references/burp-workflow.md), and unchanged model routing. R5 discovery, R6 chain, R7 impact and R8 burst grants are named classes inside this envelope's vocabulary, not exceptions to it. No private capture is sent to a new provider under this plan.

| Context code | Must be supplied | What the hunter can establish | Cannot infer |
|---|---|---|---|
| **E — external** | Exact scoped public reference; written-scope inclusion; known benign operation or owner-seeded marker (owner artifacts optional under R3) | Anonymous known-object/handler contrast; **R3 owner-absent terminators: canary write plus independent readback, synthetic intended-private read, owned account-B cross-account access** | Cloud-account inventory, ownership from DNS/IP, or permission from a provider suffix; signed bearer use is not anonymous; scope inclusion still requires written program rules |
| **L — low privilege** | Supplied disposable/short-lived identity; issuer/audience/expiry; permitted description/use; A/B canaries and expected rights | Same exact operation/resource under controlled principals and derived identities | Ambient admin profile, raw discovered-token use, unrelated role/resource rights or inferred global admin |
| **O — owner assisted** | Dated inventory/IaC/policy/scanner/log exports, collector visibility, actual deployment binding, owner intent and audit observer | Configuration facts, denied/omitted scope, candidate paths, positive baselines and attribution; owner artifacts enhance confidence and intent labels rather than gating confirmation (R3) | That lower principal A can acquire owner B's capability; a scan/analyzer result is not execution |

### Proposed readiness calculation and recursion (not installed by the offline ledger)

Each proposed edge needs `authority + owned binding + exact action/resource + supported prerequisites + approved connected channel + remaining bounds + observer + feasible cleanup`. At a future M2.5, an approved R1 channel could comprise owned account B and existing browser/Burp/native-HTTP paths under method grants; it is **not standing approval today**. An approved R6 chain grant or R7 impact envelope could replace repeated approvals only inside its written terms — neither fabricates scope. Store a reason for every missing term. New identity, service, account or data class gets a fresh edge; grants do not propagate automatically. Preserve separate technical defeating controls and execution-readiness blockers.

The proposed recursion returns to D1–D3 after a newly evidenced capability to bind resource, baseline and policy context. D8+ would close a demonstrated terminal effect/replay/cleanup but not impose an eight-hop maximum. Deduplicate cycles by exact principal/action/resource/context/version, not by hop count. End a branch when readiness is lost; preserve sibling backlog. Until the R1 account/channel is actually supplied and approved, missing tools or grants remain named blockers, never grounds for alternate SDK/curl/network execution.

## Proposed schema-1 evidence and graph contract

**This is a concrete proposed wire/data contract, not a schema accepted by today's CLI.** Implement strict validation and migrations before using it. All records live in a campaign-private namespace; a public/model export is a separately redacted projection. Never create a fake URL to fit today's URL-only finding scope anchor. ([Current finding anchor/gates](../recon/findings.py))

### Primitive types and identity rules

`Key` is a nonempty campaign-local opaque ID, not a claimed provider ID. `Ref<T>` must resolve to a record of type T in the same imported/authorized campaign context. `Sha256` is 64 lowercase hexadecimal characters computed from actual captured bytes. `Time` is RFC3339 UTC; `NativeId` retains exact provider spelling and scope. `Unknown<T>` is `{ "value": T|null, "basis": "asserted|source-observed|independently-bound|unknown", "reason": string|null }`; the basis is one listed enum value and null requires a reason. Unknown is never an empty wildcard. Every record carries `id`, `source_ref`, `collected_at`, and applicable `record_selector`; derived records cite their parent refs instead of inventing source evidence. The importer creates the root `cloud_imports` receipt from the envelope; only that receipt has null `source_ref`, avoiding a self-reference. A selector is null only with an explicit source/derivation explanation.

**Canonical identity:** `(provider, partition/cloud, scope-native-id, resource-type, native-id, version/generation)` for resources; `(provider, authority-scope, principal-type, immutable-native-id)` plus a separate session record for principals. Keep native ID case semantics provider-specific and aliases reversible. Do not merge by display name, hostname, role name, project ID/number resemblance, decoded claim, scanner UID or shared IP. Preserve application account/role/tenant/workflow labels in separate fields. Composite operation comparison changes exactly the recorded determinant; a sibling object is a counterfactual control, not proof of permission on the original object.

### Normalized import envelope

The following is a **structural template with empty record arrays**, not a captured run. Null timestamps/hash mean no import artifact exists here; an actual import requires real values. No request/provider IDs are fabricated.

```json
{
  "format": "bugvault-cloud-v1",
  "schema_version": 1,
  "source": {
    "kind": "operator-normalized",
    "tool_version": null,
    "export_schema": null,
    "source_url": null,
    "source_commit": null,
    "original_sha256": null,
    "collected_at": null,
    "collector_principal_ref": null,
    "declared_scope_refs": [],
    "visibility": {"complete": false, "gaps": []}
  },
  "records": {
    "scopes": [], "principals": [], "sessions": [], "resources": [],
    "policies": [], "inventory_runs": [], "contexts": [], "edges": [],
    "credential_refs": [], "cases": [], "events": [], "artifacts": [],
    "accounting": [], "obligations": [], "stops": [], "handoffs": []
  }
}
```

### Required record namespaces and fields

Every field below is required unless marked `?`; an unknown value uses `Unknown<T>` rather than disappearing. Slash-separated field names in this compact table mean separate fields of the stated type, not literal slash-containing JSON keys. Arrays can be empty only when that absence is known or accompanied by a gap record. Counts/byte sizes are nonnegative integers; money is nonnegative decimal with currency and explicit unknown/lag qualifications. Unrecognized keys/enum values/future versions fail before registration. The definition is normative for implementation review; it is not an implemented provider policy language.

| Proposed namespace | Typed fields beyond common provenance | Key invariants |
|---|---|---|
| `cloud_imports` | `format:string`, `exporter/version/schema:Unknown<string>`, `adapter_version:string`, `original_sha256:Sha256`, `imported_at:Time`, `collection_window:{start,end}`, `collector:Unknown<Ref<principal>>`, `declared_scopes:Ref<scope>[]`, `selectors:string[]`, `limits/errors/gaps:object[]`, `mutelist/selection_hash:Unknown<Sha256>` | Original file and normalized derivative distinct; dedup bytes + labelled context, not scanner UID alone |
| `cloud_scopes` | `provider:aws\|azure\|gcp`, `cloud_partition:Unknown<string>`, `kind:org\|ou\|account\|tenant\|subscription\|resource-group\|folder\|project`, `native_id:NativeId`, `project_number:Unknown<string>`, `parent:Unknown<Ref<scope>>`, `authority_ref:Key`, `ownership:Unknown<string>` | No hierarchy or account/tenant guessed from a host; multiple parent relationships require explicit provider evidence |
| `cloud_principals` | `scope:Ref<scope>`, `type:user\|role\|service-principal\|service-account\|workload\|federated\|service\|service-linked-role\|anonymous`, `native_id:Unknown<NativeId>`, `immutable_id:Unknown<NativeId>`, `owned_label:Unknown<string>`, `aliases:object[]`, `binding:Unknown<object>` | Assertion/decoded claims versus verified identity remain distinct |
| `cloud_sessions` | `principal:Ref<principal>`, `issuer:Unknown<Ref<principal>>`, `native_session_id:Unknown<NativeId>`, `issued/expires:Unknown<Time>`, `audience/subject/tags/source_identity:Unknown<object>`, `constraints:Unknown<object>`, `revocation:Unknown<object>` | Session and role are not the same node; no bearer material stored |
| `cloud_resources` | `scope:Ref<scope>`, `service/type:string`, `native_id:NativeId`, `location:Unknown<string>`, `version:Unknown<string>`, `aliases:object[]`, `owner:Unknown<Ref<scope>>`, `disposable:Unknown<boolean>`, `classification:synthetic\|public-intended\|private\|unknown`, `lifecycle:current\|historical\|deleted\|unknown` | Global is explicit, not an invented Region; ownership and authority are independent |
| `cloud_policy_snapshots` | `subject_ref:Key`, `kind:identity\|resource\|trust\|session\|boundary\|org-allow\|org-deny\|rbac\|rules\|key\|grant\|endpoint\|network\|other`, `version:Unknown<string>`, `artifact:Ref<artifact>`, `attachments/inheritance:Unknown<object[]>`, `parser_version:string`, `supported_facets:string[]`, `unknown_facets:string[]` | Do not normalize role ARN/session ARN or Azure/GCP policies into AWS evaluation shortcuts |
| `cloud_inventory_runs` | `declared_scopes/services/regions:object[]`, `seen_scopes:Ref<scope>[]`, `principal:Unknown<Ref<principal>>`, `pages:{seen,next,complete}`, `counts:{declared,seen,denied,error,filtered,muted,unsupported}`, `window:{start,end}`, `gaps:object[]` | Not seen, not selected, denied, disabled API and nonexistent differ; no false organization completeness |
| `cloud_contexts` | `scope:Ref<scope>`, `principal:Ref<principal>`, `session:Unknown<Ref<session>>`, `resources:Ref<resource>[]`, `action:string`, `api_version:Unknown<string>`, `method:Unknown<string>`, `path/endpoint/network/transport:Unknown<object>`, `request_context:Unknown<object>`, `app_labels:Unknown<object>`, `policy_refs:Ref<policy>[]`, `facet_hashes:object`, `as_of:Time` | All authorized resources of an operation included; exact context hash is reproducible, secrets excluded |
| `cloud_edges` | `from/to:Key`, `relation:contains\|references\|runs-as\|policy-attached\|trusts\|issues-session\|requires\|may-access\|observed-access\|consumes\|uses-key\|lineage`, `operator:AND\|OR\|atomic`, `prerequisite_refs:Key[]`, `context:Unknown<Ref<context>>`, `condition_projection:Unknown<object>`, `evidence_refs:Key[]`, `valid_until:Unknown<Time>` | Hypothesis/may-access never silently becomes observed; deny is an applicability veto, not routable negative edge |
| `cloud_credential_refs` | `opaque_private_handle:Key`, `kind:Unknown<string>`, `fingerprint:Unknown<Sha256>`, `discovery_refs:Key[]`, `issuer/principal/audience/expiry:Unknown<object>`, `permitted_use_ref:Unknown<Key>`, `chain_grant_ref:Unknown<Ref<grant>>`, `validity/permission/effect:Unknown<object>` | No tokens/keys/private-key JSON/signed URLs; discovery, identity binding, validity and consequence independent; validation/enumeration/hops run only under a recorded R6 chain grant (absent one, R2 identity-only minimum) |
| `cloud_grants` | `kind:discovery\|chain\|impact\|burst`, `scope_refs:Ref<scope>[]`, `actions:object[]`, `caps:object`, `hop_types:object[]?`, `issued/expires:Time`, `issuing_authority:string`, `receipt_ref:Key` | A grant declares its action families, caps and expiry explicitly; it never extends another grant's terms, fabricates scope or auto-propagates to undeclared hops |
| `cloud_cases` | `family:CM-00..CM-18`, `variant:string`, `objective_tier:read\|mutate\|persist\|audit-evade\|destroy-assess`, `context:Ref<context>`, `expected_boundary:string`, `intent_source:Key`, `root_key:Key`, `parents:Key[]`, `prerequisites:Key[]`, `next_edges:Key[]`, `content_assessment:Unknown<object>` using A4's defined fields, `destruction_assessment:Unknown<object>`, `triage_score:object` | Exact variant never closes siblings; unknown content retained; publicness, sensitivity and demonstrated access differ; objective tier orders probing, never inflates severity; destroy-assess is reasoned/lab-proven only, never performed on a target; root cause is not generic provider/class coincidence |
| `cloud_case_events` | Exact event shape below | Append-only chronology; immutable original context snapshot retained |
| `cloud_artifacts` | `sha256:Sha256`, `private_relpath:string`, `bytes:int`, `media_type:string`, `role:ArtifactRole`, `source_kind:string`, `source_native_id:Unknown<string>`, `completeness:complete\|partial\|missing`, `redaction:object`, `selector:Unknown<string>` | Hash same once-read bytes parsed/copied; unsafe paths/symlinks rejected; imported IDs never relabelled native |
| `cloud_accounting` | `run:Key`, `channel:string`, `provider:string`, `scope/context_ref:Key`, `origin:measured-native\|declared-external\|imported-historical`, `attempts/retries/pages/polls/exchanges:int`, `bytes_read/bytes_written:int`, `objects/resources_created:int`, `runtime/storage_commitment:object`, `cost:{currency,estimate,observed,as_of,ceiling,unknown_liability}`, `source_receipts:Key[]` | Historical imports do not re-charge; unknown attempted sends remain charged; cost is not reduced to requests |
| `cloud_obligations` / `cloud_stops` | `scope_ref:Key`, `resource/version_refs:Key[]`, `reason:string`, `owner:string`, `opened/deadline:Time`, `state:open\|resolved\|retained-approved`, `receipt_refs:Key[]`, `resume_approver:Unknown<string>`, `resume_reason:Unknown<string>` | Stop scope can be run/account/provider/resource. Recording cleanup after scope change does not authorize a cleanup call |
| `cloud_handoffs` | `source_case/event/root/context:Key`, `destination_owner:string`, `destination_anchor:Unknown<Key>`, `proven_facts:object[]`, `next_proof:string`, `readiness/accounting/obligation_refs:Key[]`, `returned_evidence_refs:Key[]` | Destination proves its own edge; no finding promotion or fake URL anchor |

### Exact event shape and evidence states

This typed definition is a proposed schema, not executable code or current wire support. `TriFact` is `{value:"yes"|"no"|"unknown", artifact_refs:Key[], selector:string|null}`. A fact with `yes` or `no` requires the applicable artifact role/completeness and semantic review; byte presence alone does not certify authorization.

```typescript
type CloudEventV1 = {
  schema_version: 1;
  id: Key;
  source_ref: Key;
  collected_at: Time;
  record_selector: string | null;
  case_ref: Key;
  context_ref: Key;
  context_sha256: Sha256;
  policy_snapshot_refs: Key[];
  authority_snapshot_ref: Key;
  occurred_at: Time;
  channel: "offline" | "owned-loopback" | "emulator" | "browser" |
           "burp" | "native-http" | "operator-cloud-tool";
  state: "unknown" | "needs-context" | "ready" | "attempted" | "pending" |
         "observed" | "negative-for-variant" | "blocked" | "missing-capture" |
         "inconclusive" | "canary-proved" | "not-applicable";
  reason: string;
  facts: {
    reachable: TriFact; authenticated: TriFact; policy_supported: TriFact;
    operation_accepted: TriFact; data_observed: TriFact; persisted: TriFact;
    identity_bound: TriFact; consumer_executed: TriFact;
    audit_visibility: TriFact; durability: TriFact;
    terminal_effect: TriFact; cleanup_verified: TriFact;
  };
  artifacts: {role: ArtifactRole; artifact_ref: Key}[];
  receipt_refs: Key[];
  marker_refs: Key[];
  content_assessment: {
    content_class: "public-asset" | "source" | "config" | "backup" | "pii" |
                   "credential-looking" | "synthetic" | "unknown";
    intended_publicness: "public-intended" | "private" | "unknown";
    confidence: "hint" | "source-supported" | "owner-bound" | "controlled";
    evidence_refs: Key[];
    selectors: string[];
    consumer_refs: Key[];
    reason: string;
  };
  parent_event_refs: Key[];
  accounting_refs: Key[];
  obligation_refs: Key[];
  evaluation: {
    integrity: "unchecked" | "valid" | "tampered" | "missing";
    applicability: "current" | "stale" | "unknown";
    semantics: "unreviewed" | "supported-bounded" | "contradicted" | "unknown";
    finding_disposition: "none" | "validator-eligible" | "rejected";
  };
};
```

`ArtifactRole` enum: `before`, `owner-baseline`, `low-baseline`, `test`, `after`, `replay`, `negative-control`, `legitimate-control`, `identity`, `consumer`, `audit`, `helper-analysis`, `cleanup`, `cost`. `receipt_refs` point to source-qualified artifact records, and `marker_refs` point to artifact selectors containing only owned inert marker metadata, not a new credential store. Store actor/operation/resource/timestamp/native source ID only if actually captured; helper/scanner IDs remain helper IDs. `stale` is applicability, not deletion of historic events. `blocked` needs a coded reason such as scope/grant/tool/policy-unknown/cost/observer/cleanup. `not-applicable` needs a supported prerequisite explanation, not missing tools or permission.

`canary-proved` needs owner positive baseline, attributable low-context effect, clean replay and genuine distinct negative control for the asserted boundary. Writes require before/after independent readback. Consumer execution requires exact artifact/version, trigger/run, actual runtime identity and downstream effect. Resulting credential/session use is a separate explicit action, never implied by a secret-looking string; an R6 chain grant is the explicit program grant that covers validation, bounded enumeration and identity hops in one standing approval recorded per hop — absent it, R2's identity-only single call is the maximum. A ledger state does not equal `findings.confirmed`; the existing semantic/reportability validator still decides, and typed resource-only anchors require new reviewed support.

### Import adapters and privacy rules

| Proposed format | Actual normalization contract | Readiness/gaps |
|---|---|---|
| **`bugvault-cloud-v1`** | Strict envelope above; operator-supplied resource/policy/identity/attempt projections and artifact refs | First implementation target; no raw token discovery or live refresh. Empty/missing scope cannot become clean inventory |
| **Prowler CSV / JSON-OCSF** | Explicit supported exporter/schema version; source scan ID/check/version; provider scope/resource ID; original verdict, lifecycle/mute and severity; collection identity/time; aggregate versus resource scope; omitted/raw field availability | Obtain owned/redacted real sample. Reviewed master source differs from release SHA. Do not claim compatibility with every 5.x build, older JSON, ASFF/SARIF/HTML or arbitrary JSON |
| **AWS owner projection** | Organization/account/partition/Region/resource ARN+version; user/role/session/principal ID; exact policy versions/attachments/trust/boundary/session/org controls; actual BPA/ownership/KMS/key/grant/endpoint configuration and visibility | A normalized local projection, not an AWS SDK/API response importer. Preserve newer fields and unsupported semantics as unknown |
| **Azure owner projection** | Tenant/subscription/group/native resource; object/app/SP/managed identity; assignment scope, control/data-plane actions, conditions/denies/Policy; vault mode; deployment/run/version; collector permission gaps | Generic storage only until primary semantics/schema review; no Entra/ARM/Graph raw-API adapter promise |
| **GCP owner projection** | Organization/folder/project ID+number; full resource name/generation; principal/SA/workload subject; hierarchy allow/deny/conditions/org-policy/perimeter; actual runtime/scopes/build identity; collection APIs/pages/gaps | Generic storage only until primary semantics/schema review; direct federation versus impersonation kept distinct |

Prowler's actual [output model](https://github.com/prowler-cloud/prowler/blob/a5fd2d7eda90e9d59e0c4bfc0c74284b47529694/prowler/lib/outputs/finding.py), [OCSF mapping](https://github.com/prowler-cloud/prowler/blob/a5fd2d7eda90e9d59e0c4bfc0c74284b47529694/prowler/lib/outputs/ocsf/ocsf.py) and [reporting guide](https://github.com/prowler-cloud/prowler/blob/a5fd2d7eda90e9d59e0c4bfc0c74284b47529694/docs/user-guide/cli/tutorials/reporting.mdx) are the source basis, not implementation evidence. Filters/muting do not establish which collector APIs were never called. Retain intended versus scanned subscriptions/projects and service/API errors; never infer organizational completeness from fallback enumeration.

Proposed engineering ingestion limits: **2 MiB envelope, 2,000 records, 5,000 edges, nesting depth 32; 5 MiB per artifact and 25 MiB unique artifact bytes per transaction**. These are parser/resource-safety choices, not hunt-depth or coverage limits; revise through tested schema/config review, not silent truncation. Validate entire envelope and joins before writes; atomic transaction or no registration. Reject unknown keys, unsafe paths/symlinks, malformed IDs, excessive nesting, ambiguous versions and unredacted credential-bearing fields. Preserve unsupported records as counted gaps. Treat all imported prose as untrusted data, never instructions. Review exports as private; regex masking is not universal DLP. Keep original credential-bearing captures, when permitted at all, outside model-facing packets under existing private evidence controls.

## Proposed skill, CLI and repository integration

**Installed skill:** `.claude/skills/hunt-cloud-misconfig/SKILL.md`; **coverage class:** `cloud-misconfiguration`. The shorter ID is wired in `recon/skillmap.py` and catalog; the installed count is **26 skills = 18 hunts + 8 guides**. A trigger selects a workflow, not permission or a finding. The following table is the **proposed full CLI contract**, not a list of currently missing or currently installed commands; use the checkpoint and `recon cloud --help` for actual verbs.

| Proposed full offline verbs (some partially installed) | Contract |
|---|---|
| `import`, `sync`, `declare` | Parse approved artifacts, reconcile existing snapshots, declare exact operations; no resolution, SDK discovery or target queueing |
| `generate` (partially installed) | Current command records scope-checked program-hostname proposals from operator-supplied words only; future provider-namespace derivation/ownership, live discovery and shared traffic accounting are not installed |
| `inventory`, `graph`, `plan`, `show` | Display source/ownership gaps, conditional/evidenced edges, case applicability/readiness and smallest next proof |
| `record`, `handoff` | Append source-qualified event and transfer class-specific proof responsibility; no request execution, credential use or promotion |
| `cleanup`, `resume` | Record exact restoration/deletion/retention and reviewed stop reconciliation; no teardown API or traffic authorization |
| `status`, `verify`, `export` | Show denominators/open variants; rehash/rebind and report tamper/stale/missing; export bounded redacted packets |

`recon/cloud.py`, `recon/cloud_refs.py` and `tests/test_recon_cloud*.py` now exist as an offline slice. `cloud_identity.py`, `cloud_inventory.py`, a fully typed store migration/graph and provider adapters remain future work. Review the dirty working tree before any edit; do not overwrite unrelated changes or protected plans.

Add the shared pure `cloud_references()` implementation in `recon/extract.py` or a focused `recon/cloud_refs.py` module exposed through that shared interface; cloud/JS/API consumers must not maintain diverging copies. Proposed reference/readiness/content/RUM task cards belong under the future skill's references and evals, with source status explicit.

Revised integration order is **shared extraction with R4 triage → minimum typed ownership/context/provenance → exact-operation events/readiness/content/cleanup with R2 objective axes → R1 owned lab and probe channel (M2.5) → anonymous/mutation slice with R3 terminators, skill/CLI/catalog/coverage/report → RUM card validation and broader identity/graph → sample-backed Prowler adapter as worklist/visibility only → further provider contexts**. Typed resource anchors and exact chain lineage must exist before recording resource-only findings; do not fake a URL or postpone evidence correctness to make the slice appear complete. Touch `recon/campaign.py`, `score.py`, `skillmap.py`, `catalog.py`, `cli.py`, `report.py`, `findings.py` and `chain.py` only when each feature has tests. Retain `pack:s3-perms` as a suggestion and existing `cloud-metadata` history as an SSRF primitive; do not silently migrate historical findings. Resource/host/service coverage should attach to exact cloud candidates even without an application endpoint; scoring is priority, not severity/confidence/testedness.

### Case taxonomy and report-matrix mapping

Every family expands by provider/scope/principal/action/resource/context/version. It is not a fixed assertion count or exhaustive service catalog.

| Proposed family | Worklist purpose | Full report family |
|---|---|---|
| CM-00 | Authority, ownership, identity and inventory baseline | All |
| R2 objective axis | `objective_tier` cross-cuts every family; at equal readiness, mutate/persist/audit-evade/destroy-assess outrank read | All |
| CM-01 / CM-02 | Storage read/list versus write/overwrite/delete, separate operations | F01 |
| CM-03 | Presigned/SAS/signed delivery and issuance constraints | F02 |
| CM-04 / CM-12 | Service authentication/data access versus network/perimeter/endpoint policy | F05 |
| CM-05 / CM-06 / CM-14 | Effective IAM/RBAC, trust/cross-scope, inheritance/conditions/deny | F03, F10 |
| CM-07 / CM-09 | Federation/workload identity versus metadata acquisition boundary | F03, F04, F08 |
| CM-07 / CM-08 / CM-15 RUM subvariants | Browser bootstrap/monitor reference → actual identity and scope → unintended owned-resource effect; A3 adds a specific candidate card, not a new automatic finding class | F03, F12 plus A3; primary RUM validation pending |
| CM-08 / CM-10 | Credential lineage/validity/use versus secret/config value access | F09, F12 |
| CM-11 | Snapshot/backup/image/registry/package/state/export lifecycle | F07, F11 |
| CM-13 | CDN/origin/CORS/cache exact application/browser effect | F02 |
| CM-15 | Service execution, artifact consumer, CI/CD, Kubernetes and recursive escalation | F06, F07, F08 |
| CM-16 | Stale resources/name references/versions/autonomous writers | F13 |
| CM-17 | Shared responsibility/security posture and observability | F14 |
| CM-18 | Replay, semantic validation, dedup, report and cleanup closure | All |

### Handoff ownership is exact, not campaign-wide class matching

| Existing owner | What it retains | Cloud work added |
|---|---|---|
| `hunt-js-bundle`, static/API/APK mapping | Artifact/build/endpoint and secret-pattern provenance | Owner/resource/issuer binding and actual permission/effect; no raw key packet |
| `hunt-ssrf`, `hunt-ssti` | Server fetch/template/file-read causality and depth grants | Independently approved cloud identity/use/resource consequence; no hidden acquisition hop |
| `hunt-file-upload` | Intake/storage/processing/publication/retrieval/deletion | Provider resource/authz and exact signed-delegation scope, sharing object lineage |
| `hunt-access-control`, `hunt-idor` | Function/field/tenant policy and owned-object substitution | Provider IAM/trust/data-plane context; no evidence borrowed from another principal/resource |
| OAuth/SAML/auth/MFA/ATO owners | Assertion/exchange/login/account semantics | Accepted cloud identity and exact role/resource capability; token receipt alone is insufficient |
| `hunt-takeover` | Current claimability, owned claim, exact-host delivery, TLS/browser consumer, cleanup | Cloud resource lifecycle and actual writer/consumer identity; no automatic claiming |
| XSS/CSRF, business logic/race owners | Browser execution/initiation or owned invariant/schedule causality | Proven cloud mutation/consumer edge under same lineage; no inferred concurrency from imports |

Each packet carries source/context/policy/artifact hashes, native scoped identity/resource/version, app labels, observed versus hypothesis facts, root/parent refs, next proof, branch readiness, remaining bounds and cleanup. A cloud chain cannot resolve from unrelated same-host or campaign-wide class matches. Findings remain subject to the existing replay, negative-control, privilege-versus-impact, realism and reportability review. ([Current validator](../recon/prompts/validator.md); [chain limitations](../research_notes/Cloud%20misconfiguration%20hunting%20plan/bugvault-audit.md))

## Live-connector decision and shared accounting

**Proposed R1 decision, not installed cloud execution:** a future M2.5 release could use operator-initiated probes through existing approved channels (dedicated browser/Burp, `recon send` with method grants) and a separately provisioned owned account-B lab. The current cloud ledger dispatches no requests and has no account-B setup. Future SDK/CLI/scanner use still needs separate written approval and an engineering decision: retain a bounded human-operated external tool/import path, or build a reviewed mediated connector. An approved scanner/native HTTP plan is not automatically an SDK grant. An offline recording gate does not constrain traffic. Default browser/Burp and current native HTTP limits remain intact. ([Execution boundary](../AGENTS.md#execution-and-evidence))

Before any connector, design operation/resource/audience binding, credential custody and provider selection, signing, every network destination/redirect, retries/pagination/token exchanges/async polls, cancellation/unknown writes and auditable receipts. Never let SDK ambient credential discovery pick a personal/admin identity. Provider RPC classification needs both **API action semantics and HTTP method**: POST read RPC still needs current method permission; key-returning “read” still needs sensitive-content permission. Review exact collector dependencies, not merely check filters. Any allowed service-mediated role/config mutation is its own operation with before/after/cleanup, not an evasion of a real deny.

One campaign envelope reconciles every channel. Suballocate per provider/account-or-tenant/project, service/operation, run and time window; aggregate back to campaign totals. Count attempted sends, failed/uncertain sends, retries, redirect hops, pagination, polls, token exchanges, identity hops, bytes and created objects/resources. Cost commitments include compute/job/build runtime, storage/version/backup retention, request charges and applicable egress; creation count alone is insufficient. Record estimated versus observed cost, observation lag, currency, maximum liability and cleanup reserve. Do not invent current prices or call any lab free. Reserve room for baseline, replay, controls, readback and cleanup; caps must come from the owner. Offline imports never charge already completed traffic twice. Manual external declarations remain visibly different from measured native calls, and neither claims an atomic cross-process broker.

Stops attach to the affected run/account/provider/resource with reason, uncertain-effect liability and cleanup obligation. New credentials, channels or models cannot clear them. Reviewed `resume` reconciles counts, actual state, current rules and cleanup receipts; it does not itself send traffic. Cleanup recording remains available even after readiness is withdrawn, but any external cleanup operation still needs applicable authority and a safe approved path.

## Milestones, dependencies and acceptance

| Milestone | Deliverable / dependency | Exit condition |
|---|---|---|
| **M0 / P0 research** | These two files; four-resource pins/license/source conflicts; no current campaign/SDK approval | Written engineering/hunt contract only. Not permission, implementation or a passed gate |
| **M1 shared references (A1)** | Pure shared parser, exact provenance/spans, aliases/scope gaps, RUM/Cognito/Firebase hooks and redacted outputs | Extraction/identifier/redaction/no-network tests pass; references are not ownership or permission |
| **M2 minimum evidence foundation (A2/A4)** | Minimum typed ownership/principal/context/provenance, AWS operation cards, exact event facts/content/replay/control, cleanup/accounting/verify | Exact-operation mismatch/tamper/stale/unknown tests pass; no full IAM solver or graph required; external declaration is not enforcement |
| **M2.5 execution-first path (R1)** | Operator-owned adversary account B (lowest tier, no production trusts/data); probe channel through existing browser/Burp/native-HTTP with method grants; accounting, stops and events wired to both surfaces | Identity call + one-action probe + matched negative control demonstrated end-to-end on account B; zero probes outside written scope; no SDK, ambient credentials or automatic dispatch |
| **M3 anonymous/mutation vertical release (A2/A4 + R2/R3)** | Known-object/list/write/service and mutation-first ordering; R3 owner-absent terminators; R4 triage queue feeding case selection; skill/CLI/catalog/coverage/report; typed finding/chain anchors and smallest vulnerable/fixed owned fixtures | Useful reference-to-disposition path works before Prowler; applicable Gate A and B-local rows pass, remaining rows stay open; probes only operator-initiated through the R1 channel under grants — no automatic dispatch or false findings |
| **M3.5 discovery/pivot/impact lanes (R5–R7)** | Deterministic candidate generator consuming A1 plus scope-declared namespace patterns; chain-grant hop recording with derived principals as first-class hunting principals; impact-envelope proof classes with caps/readback/cleanup receipts; R8 burst-cap declarations in run plans | Generation volume pre-declared and accounted, foreign-tenant collisions ownership-ambiguous; hops only under recorded chain grants; real effects only inside envelope classes; parallel branches share one budget |
| **M4 specific depth and graph (A3/A4)** | Primary RUM/Cognito configuration review and candidate card; content-driven handoffs; expand identity/session/policy/consumer graph and cases | Expected public bootstrap/ingestion does not confirm a bug; each deeper edge needs independent permission/context/proof; unsupported semantics unknown |
| **M5 sample-backed scanner adapter** | One actual owned/redacted Prowler version sample; strict CSV/OCSF mapping, visibility denominators and exact resource handoffs | Only supported versions advertised; scanner verdict is not impact; worklist/visibility source only, never a confirmation dependency (R3); no fixer, secret validation or scanner dispatch |
| **M6 owned acceptance and approved provider pilot** | B-cloud sandbox fixtures expand execution beyond the R1 lab/probe channel; Gate A and selected B-local completion, approved Gate C judgment, full regression; separate fresh scope/actions/sandbox/path/budget/observer/cleanup go/no-go | Local/model gates do not certify provider behavior; pilot acceptance only for actually tested cases with residual access/resource/cost review |
| **M7 expand contexts (R8 parallel track)** | Azure/GCP primary review, semantic cards and generic implementation in parallel with AWS certification; further real artifact versions/services and owner-approved scopes | Certification claims wait on each provider's own primary review; per-case/provider/context acceptance and visible gaps; never “full cloud covered” |

### Gate A — deterministic schema, policy and evidence correctness

Build a requirement → test → result → limit matrix, not merely an aggregate passing count. Mandatory cases:

- **Schema/migration:** legacy campaigns unaffected; strict versions/keys/limits; atomic malformed import; idempotent byte/context duplicates; later scans retained; malicious imported prose, unsafe paths/symlinks and cross-scope/dangling refs rejected.
- **Shared extraction (A1):** cloud/JS/API consumers use one parser; source selector/hash round trip, URL aliases, provider-native scope collisions, errors/CT/upload references, archived/truncated artifacts and malformed strings; no signed URL/token leakage or target queueing, and no parser-side generation/validation/resolution — R5 generation and R6 validation are separate granted components, never parser side effects.
- **Anonymous slice (A2):** independent existence/list/read/write/service cases; known-object read need not follow listing; denied listing does not prove privacy; signed URLs/SAS/cookies/ambient SDK identity cannot be labelled anonymous; accepted write without readback/control/cleanup does not prove persistence or impact.
- **RUM/bootstrap (A3):** public monitor/pool/browser identifiers and expected telemetry-only access are non-findings absent another boundary; configuration, identity binding, effective scope and canary effect are separate facts; unsupported/currently unverified identity flows remain unknown and cost/event-volume bounds remain enforced.
- **Content and next proof (A4):** identical read success yields different disposition for public-intended assets versus intended-private synthetic source/config/backup; credential-looking is not validity; consumer reference is not execution; unknown labels stay observable/inconclusive without forced retrieval or invented sensitivity; routing preserves exact context/authority and redaction.
- **Native identity:** same names in different accounts/tenants/projects remain distinct; AWS partition/role/session/immutable ID, Azure tenant/subscription, GCP project ID/number and explicit global location; unverified claim never upgraded by parsing.
- **Scanner interpretation:** PASS/FAIL/MANUAL/muted and OCSF lifecycle independent; aggregate account PASS not copied to every bucket; missing raw/UID/name, default inventory omissions, denied pages/API disabled/fallback projects all counted unknown; no fixer/secret-validation/SDK/DNS/network/queue side effect.
- **Provider policy subset:** exact explicit-deny applicability; same-account AWS principal-grant forms not flattened; bilateral cross-account prerequisites; SCP/RCP/service/key/endpoint/session distinctions; missing condition keys, unsupported action/dependency and missing inheritance → unknown. Preserve analyzer/simulator claims separately and test documented-source conflict disposition.
- **Delegation false positives:** public browser/Firebase config not a secret; unsigned/expired SAS or signed URL, wrong object/method/version/audience/scope not borrowed as access proof; account permits public storage ≠ anonymous blob read; identity-only success ≠ effective permission.
- **Proof:** source-qualified native IDs cannot be invented or relabelled; owner baseline is not negative control; same marker/content/hash reused as control fails; exact wrong principal/resource/action/Region/version fails; incomplete capture cannot prove absence; accepted write without persisted readback remains unknown; same-host/unrelated finding cannot prove a chain.
- **Integrity/staleness:** hash the once-read bytes actually parsed/copied; mutate/delete artifact or policy/context facet → visible tamper/missing/stale; relevant policy/session/revision changes reopen dependent cases without deleting history.
- **Accounting/limits:** measured native versus declared external versus historical import; requests/retries/pages/polls/exchanges counted once; uncertain sends charged; SDK traffic outside mediation never labelled enforced; bytes/objects/runtime/storage/price/lag/currency/cost-cap labels preserved; unknown liability blocks new affected work.
- **Stops/cleanup:** scope/principal drift, 429/challenge/5xx, lost observer, unknown write, sensitive-data spill, budget/cost expiry and failed teardown propagate to declared scope; channel/model switch does not resume; exact resource/version receipt or owner-approved retention obligation required.
- **Integration:** only implemented verbs/counts; bounded redacted packets, class owner/handoff and root keys; no fake finding URL; untested/missing contexts remain visible despite coarse coverage.
- **Execution channel (R1):** probes leave only through approved existing channels with current method grants; zero out-of-scope destinations; account B isolated from production trusts/data; every probe event links accounting, negative control, readback and cleanup; a missing grant records `blocked`, never a transport workaround.
- **Objective tier (R2):** tier ordering deterministic at equal readiness; a mutation probe requires its operation grant, readback and cleanup; `destroy-assess` cannot be recorded as performed on a target — reasoning and owned-lab evidence only; identity-only credential validation requires its explicit program-grant record.
- **Owner-independent confirmation (R3):** each terminator reaches `canary-proved` only with its own replay and distinct negative control; scope inclusion derives from written rules only; absent owner input, intent labels stay `unknown` rather than manufactured; owner artifacts shift confidence, never replace proof.
- **Triage (R4):** identical reference inputs produce identical ordering; staleness decay applied; tie-breaking deterministic; no fabricated ownership, permission or namespace from a score.
- **Discovery lane (R5):** candidates derive only from scope-covered namespace patterns and target-derived tokens; foreign-tenant collisions marked ownership-ambiguous and never probed further; generation volume pre-declared, accounted and 429-backed-off; no keyspace brute force or credential spraying.
- **Chain pivot (R6):** validation, enumeration and hops run only under a recorded chain grant with a declared API allowlist and stop conditions; each hop is an exact-operation event; credential material never persisted; out-of-scope resources and real-user data stop the chain cold.
- **Impact envelope (R7):** real-effect proofs only within declared classes and caps; only canary targets deletable/overwritable; real-user personal-data exfiltration rejected at validation time; restore/readback/cleanup receipts required; parallel branches share one budget envelope.
- **Burst budgets (R8):** elevated attempt caps exist only as declared run-plan values under written scope; undeclared work falls back to defaults; provider rate signals always respected.

### Gate B — local vulnerable/fixed proof, then separate actual cloud proof

**B-local:** paired owned-loopback/emulator fixtures exercise storage read/list/write/delegation, IAM-looking allow defeated by deny/conditions, identity-only success, authenticated public service, secret metadata versus value, artifact stored versus consumed, actual consumer identity versus supplied label, snapshot-copy lineage and cleanup failure. Each needs vulnerable effect, one-edge fixed denial, legitimate positive control, distinct negative control, clean replay/new marker, independent state readback, normalized import, status/verify/report and cleanup. Add the R2 full-chain rehearsal in owned account B — read → escalate → mutate (policy/credential creation) → persist (survive rotation/revocation) → destroy (marker-only "mass delete" of canary objects across versioning states) — each step with fixed and negative controls and full cleanup, so target-side proofs can be minimal synthetic equivalents of the same rated capability. In-process/emulated IAM validates the model only. No simulator proves real AWS/Azure/GCP semantics.

Run the anonymous known-object/private-control fixture during M3, not after the scanner adapter. Include provider-labelled parsing fixtures without presenting them as real-provider tests; public-versus-private content routing, list-denied/read-allowed contrast and signed-versus-anonymous context are mandatory. Add an owned synthetic telemetry/identity fixture for A3 when its card is specified, clearly separating expected event ingestion from a canary-only excess permission; it is not actual CloudWatch RUM validation.

**B-cloud:** approve fixtures individually or as a parallel set under one R7 impact envelope with per-branch caps. Start with storage/delegation and canary-only service-role delegation; add wrong-subject federation, artifact consumer, metadata, Kubernetes, Azure ADF, snapshot/queue/peer branches as actual permissions/semantics/costs permit. Preserve separate deployer and participant, no production trusts/data/users, exact scoped canary grants, bounded actions and observable ready states; under an R7 envelope, canary-object delete + version restore is a permitted real effect on targets, while destruction of non-canary production data is never performed — capability is proven by the canary equivalent. Require real provider/source receipts for **every** identity/activation/action edge, matched fixed/negative/legitimate controls, fresh replay, restored denial, independent inventory of resources created outside state, session/credential revocation where supported, retained-item owner/deadline and account cost reconciliation. CloudGoat destroy/reset text is not cleanup verification. ([Lifecycle implementation](https://github.com/RhinoSecurityLabs/cloudgoat/blob/63c65bd26edc6919499adfa20b176c450e35c33c/cloudgoat/core/python/commands.py#L388-L569))

Passing local fixtures does not pass B-cloud. A provider pilot does not pass other providers/services/contexts; eligibility failure becomes a named untested branch rather than an account/network workaround.

### Gate C — semantic skill judgment with a valid baseline

Use fictional/redacted cases across all families: public-by-design key, NoSuchBucket/provider suffix, arbitrary scanner JSON, all-address firewall with strong auth, AWS allow-plus-deny, partial org inventory, malformed session identity, wrong OIDC subject, expired SAS, unconsumed image, source-secret reference, same-host unrelated chain, missing browser/SDK permission, read RPC over ungranted POST, cost drift and unresolved cleanup. Predeclare expected owner, source facts, unknowns, next exact proof, blocked edge, stop and report disposition.

The adopted additions require explicit judgment cases for shared-reference provenance, list-denied/read-unknown versus a captured exact read, signed delivery mislabelled anonymous, RUM public IDs/expected ingestion versus independently evidenced excess scope, and public/private/unknown content with the correct next-proof handoff. R1–R4 add: mutation-first ordering at equal readiness; accepting a valid R3 terminator where one exists and refusing an owner-artifact shortcut where none does; destroy-assess reasoning versus performed destruction; identity-only credential validation with and without its explicit grant; triage tie-breaking, stale decay and ranking reproducibility. R5–R8 add: a foreign-tenant collision staying a non-finding; a chain-grant boundary stop (out-of-scope hop refused); envelope-class selection between synthetic marker and real effect; "could-read" versus demonstrated exfiltration-to-owned-receiver rating difference; burst caps declared versus defaulted. Do not use `content_class=unknown` as a reason to erase a real observation or infer a finding.

Only with model-execution/data approval, run skill versus **clean isolated without-skill baseline** using the same model/task/rules; save requested/actual model metadata, outputs, graders, case denominators, failures and reruns. Require zero critical authorization/evasion/false-confirmation errors in this acceptance set; report every other score and uncertainty. Blind semantic grading where feasible. Contaminated baselines are retained and explicitly invalid/excluded, not repainted as an improvement. Static fixture tests are not behavioral Gate C. ([Prior takeover evaluation caveat](../docs/takeover-acceptance.md))

**Regression:** implementation must rerun the full then-current suite and record interpreter/version/date/count/skips/failures. Preserve **674 passed** as the *pre-cloud research* checkpoint, not a fixed future total. The offline slice has its own actual test result in the handover; Gate A/B/C as a whole remain open. The initial research synthesis itself ran no acceptance gate.

### Per-case done criteria

A case can be complete **only for its named provider/context/operation/resource/version/variant** when source/authority/ownership and capture completeness are explicit; the intended boundary is sourced; effect has independent readback/attribution; relevant prerequisites compose; replay and true negative/legitimate controls hold; policy/timing uncertainties are bounded; semantic validator disposition/root grouping is recorded; and cleanup/access/cost obligations are satisfied or explicitly owner-approved retained. Refuted/blocked/inconclusive variants retain their artifacts and reopen trigger. A family/global complete flag cannot override open cases, unsupported services, missing accounts or denied pages.

## First hunt worksheet and day-one checklist

This is a **finite future operator worksheet**, not a run already performed. Start with one lead and one smallest useful canary boundary; every additional branch receives another worksheet linked to the parent.

| Field | Fill before an approved live exercise; otherwise name the missing dependency |
|---|---|
| Campaign/window/approver | Written program/rules/hash/review date; provider-policy review; model/evidence sharing permission |
| Context and source | E/L/O; exact captured reference or export hash/selector; collection time, source/check/tool version and completeness |
| Ownership/scope | Provider/cloud, org/account/tenant/subscription/project, Region/global, exact native resource/object/version and ownership proof; exclusions |
| Principal/session | A and legitimate B, source of supplied identity, issuer/audience/expiry, app account labels separately; no raw credentials |
| Hypothesis | “P can do A on R/version via T contrary to B under C”; expected baseline and terminal synthetic effect |
| Objective tier / triage | R2 tier targeted and why it outranks siblings; R4 score, rank and decay; chosen R3 owner-absent terminator or the named owner artifact |
| Operation | Exact service API/action, authorized resources, HTTP method, network/endpoint path and expected side effects |
| Policy/config | Relevant grant/trust/deny/hierarchy/session/network/key/revision snapshots, versions/hashes; unknown facets and defeating controls |
| Proof/control | Owner positive, low baseline, unique test marker, before/after readback, replay/new marker, single-edge negative and legitimate fixed control |
| Execution readiness | Existing written action/channel grant and connected path; actual observer/receiver; if absent, owner lab/evidence handoff |
| Bounds | Remaining campaign plus account/API attempt/rate/time/byte/object/runtime/storage/cost caps; replay/control/cleanup reserve; measured vs declared |
| Evidence | Expected real source receipts, artifact roles, redacted selectors, temporal window and immutable once-read hashes |
| Content/bootstrap assessment | A4 class/publicness/confidence, actual evidence and consumer refs; unknown reason; for RUM, expected ingestion, actual identity flow and separately evidenced excess permission |
| Cleanup/next edge | Exact resources/versions/revisions/bindings to restore/delete/revoke, owner/deadline/cost follow-up, stop/resume route; next capability needs fresh readiness |

Day one, with **no live approval supplied yet**, is finite:

- [ ] Choose the owner decision-maker and one context, not an assumed credentialed scan.
- [ ] Receive/review written scope, applicable provider rules and evidence-sharing constraints; list unresolved decisions.
- [ ] Run A1 extraction across stored artifacts, apply the R4 triage score and take the top-ranked references per lane; collect source hashes/labels offline; namespace generation only through a granted R5 lane.
- [ ] Bind one exact resource per selected reference at the highest ready R2 objective tier; prefer a mutation or account-B terminator probe where writability/cross-account access is plausible; record the ownership request only where still required.
- [ ] Confirm the R1 channel state — owned account B provisioned, method grants current, accounting wired — or name the missing grant as the blocker; never substitute another transport.
- [ ] Where R5/R6/R7/R8 grants exist, declare generation dictionaries and volume, chain allowlists, envelope classes and burst caps in the run plan; where they do not, record those lanes closed rather than improvising.
- [ ] Build its policy/consumer dependency card, direct baseline expectation, defeating controls and smallest terminal effect.
- [ ] Name operation/channel/budget/observer/cleanup prerequisites; request only those missing from a standing plan.
- [ ] Draft exact before/test/after/replay/negative/legitimate-control artifact roles and new-marker requirements.
- [ ] If all terms are genuinely ready later, conduct only the approved bounded exercise through its approved path; otherwise hand the precise worksheet to the owner for isolated proof, without alternate transport.
- [ ] Reconcile any actual attempts, facts versus unknowns, next edge and obligations; report no unperformed result.

### First two weeks: example delivery schedule, not an execution promise

| Time | Finite deliverable | Dependency / honest fallback |
|---|---|---|
| **Days 1–2** | M0 review and A1 shared extraction contract/fixtures; choose one AWS H1 anonymous boundary and preserve H2/H3 backlog | Existing artifacts or labelled synthetic fixtures only; ownership remains independently required |
| **Days 3–4** | Finish M1 parser and M2 minimum typed provenance/context/evidence, including A4 assessment; provision account B and stand up the M2.5 R1 probe channel; initial Gate A regressions | Defer broad graph/scanner work, not identity/proof correctness; unknown fields remain explicit; channel stands only under current written grants |
| **Days 5–7** | M3 reference-to-disposition slice with R2 mutation-first ordering and R3 owner-absent terminators, skill/CLI/catalog/coverage/report and typed anchor/handoff integration; R2 full-chain rehearsal in account B; vulnerable/fixed B-local proof | Probes only operator-initiated via the R1 channel; denied list is not privacy; separate signed contexts and grant any disposable writes independently |
| **Days 8–9** | M4 RUM/browser-bootstrap primary review/card and content-driven depth; R4 triage tuning against accumulated probe outcomes; expand only necessary identity/consumer graph; full regression and approved Gate C work | RUM identity mechanisms remain unverified until reviewed; local telemetry fixtures are not real service proof; triage order stays deterministic |
| **Day 10** | Review the first release and open acceptance rows; prioritize M5 sample-backed Prowler work and M6 separate provider-pilot decision | Adapter and pilot are later dependencies, not first-release prerequisites or promised day-ten execution; Azure/GCP primary review stays explicit |

This schedule is an engineering example, not a commitment to finish unknown integration work in ten days. Each failed acceptance row remains open and the next milestone waits on its actual dependency.

## Useful metrics and owner decisions

Measure **controlled boundary failures**, accepted root causes and independently proven chain edges, not failed-check volume. Report denominators for declared/scanned/denied/unsupported resources and contexts, ownership-binding rate, time to smallest valid proof, unknown-policy proportion, control/replay completeness, stale-case reopening, cost per accepted boundary, uncertain-attempt liability and overdue cleanup/residual resources. Separate potential severity, source confidence, demonstrated effect and report disposition. Avoid provider-wide coverage percentages with unknown denominators. Add R-lane metrics: top-N triage precision (confirmed per attempted probe), time-to-executable-proof, mutation/persistence share of accepted findings, owner-independent confirmation rate, account-B rehearsal completion and out-of-scope probe count (target zero). Round 2: candidate→bound→confirmed funnel rate, chain-hop depth to terminal effect, envelope proof-class usage and restore-receipt completeness.

Open owner decisions, none supplied as approved here:

1. Which written program and AWS sandbox/account/resources are first; external-only, supplied low role or owner-assisted?
2. Who supplies A/B principals, canaries, current policies/audit observer and an owned/redacted Prowler sample/version?
3. Which exact read/write/exchange/role/deploy/execute/restore operations, provider policy and disposable resource scopes are granted?
4. What approved execution path exists, and will future SDK use remain operator-run/imported or receive a separately reviewed connector?
5. What numeric campaign/account/API/rate/time/byte/resource/cost limits and cleanup reserve apply, and who reconciles unknown writes/retention/billing?
6. What typed resource finding anchor and exact chain lineage change is accepted without weakening current gates?
7. Who approves Azure/GCP primary semantic/default/policy review and later service-specific gaps, licensing reuse if ever needed, and a clean model evaluation?
8. Who provisions and pays for owned adversary account B, and which target-side read versus mutation method/operation grants does each program permit through the R1 channel?
9. Does each program's written policy explicitly permit R2's identity-only credential validation call, and what destroy-assess evidence format will its triage accept?
10. Which programs issue R5 discovery, R6 chain and R7 impact grants, with what dictionary limits, hop allowlists, envelope classes and caps?
11. What R8 burst-cap values does each program accept for enumeration runs, and how are they reconciled with provider rate signals?

Critical source issues to preserve: **AWS KMS grant-key case sensitivity, Access Analyzer analysis-type wording and source-identity length conflict; Prowler read-only labels versus actual sensitive/write actions and distinct master/release SHA; CloudGoat catalog/reset/destroy/protection claims versus source behavior; Azure/GCP secondary defaults and current HackTricks license not established**. The full report links both sides. These uncertainties are targeted readiness/acceptance work, not a reason to flatten the plan into passive scanning or pretend technical/authorization obstacles do not exist.
