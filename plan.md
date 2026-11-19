# BugVault access-control and mass-assignment hunting plan

**Date:** 2026-11-14

**Status:** Approved for implementation on 2026-11-14. Offline workflow implemented and tested; **no live target/pilot was authorized**.

**Implementation checkpoint:** See §11 for completed pieces and remaining lab/pilot limits. This plan is not itself a campaign authorization or a finding.

## 1. Scope decision — one skill, two existing classes

The proposed `hunt-access-control` skill is **about broken access control and mass assignment in full**, not a subsection of a generic API-misconfiguration skill. After approval, map exactly:

```text
access-control   -> hunt-access-control
mass-assignment  -> hunt-access-control
idor-bola        -> hunt-idor  (unchanged)
```

The skill's nine case families are eight access-control paths (`ac-unauth`, `ac-role`, `ac-tenant`, `ac-method`, `ac-version`, `ac-projection`, `ac-transport`, `ac-surface`) and one mass-assignment case (`ma-privileged-field`). Its organizing question is: **which different entry points reach the same protected function, field, or dataset, and does each enforce the intended policy?** A discovered sibling is a hypothesis; an unauthorized effect with controls is evidence. The method is reusable on any *authorized* target but never implies blanket permission to test every API or every variant.

The skill is written to pursue **critical impact first**, not to audit coverage evenly: case order and effort are weighted by the sensitivity of what a bypass would expose, and a confirmed intermediate result can open the next rung of a chain (§2). Aggressive probing is real but **granted**, never assumed.

This supersedes the broader `api-misconfig` class, `hunt-api-misconfig` skill and `recon/api_config.py` proposed in the earlier version of this file. CORS, cache, transport hardening, exposed docs/debug endpoints, quota/DoS, proxy trust, JWT/OAuth, SSRF, prototype pollution, SQLi and XXE are **not** nine hidden subcases. Keep their existing owners where available, or plan them separately later. Their behavior can be *context* — or a granted `read-extraction` probe surface — for an access-control finding, but this skill should not issue a second report for the same root cause.

## 2. Hunting posture — impact-first and granted-aggressive

The plan is a hunter's playbook, not a coverage audit. Four posture rules apply to every case in §6.

**2.1 Impact-first priority.** Each case card starts with the critical effect it could unlock — cross-tenant data, an admin-only function, credential or token exposure, internal topology, destructive or persistent state — and with the next rung if it succeeds. Open hypotheses are ranked by that potential impact, not by row order or by how cheap they are to tick off. A case that cannot plausibly reach a sensitive effect is parked quickly; one that can is pursued to its proven extent.

**2.2 Chain ladder.** A confirmed intermediate result — another context's data, a usable token or secret, an internal address, a role change — is fuel, not a finish line. It opens a follow-on hypothesis:

```text
read leak -> identity/role confusion -> token or credential use -> lateral/admin effect -> persistent or bulk extraction
```

Each rung is a separate hypothesis under the same scope and evidence standard, and each needs its own grant: the SSTI precedent (`ssti.depth_grants`, with offline `cred-read`/`token-use`/`lateral` recording) is the model, and this skill's rungs are `token-use`, `lateral` and `persistence`. The engine records the rung; the operator executes it in the dedicated browser/Burp. The engine never uses a credential, moves laterally, keeps access, or exfiltrates a dataset. A chain is reported as one root cause with its proven extent, not as a pile of case events.

**2.3 Granted aggressive probes.** The default remains read-only observation, but the plan no longer bans every expansion. A campaign may grant, per target and host, a bounded probe family from the workflow (§5 step 5): `method-matrix`, `sibling-expand`, `representation-fuzz`, `id-mutation`, `read-extraction`, and optionally `write-proof`. Ungranted means refused and recorded as blocked, not silently "not applicable." Every probe stays inside scope, method, rate and budget.

**2.4 Sensitive-data impact layer.** "Find something sensitive" is an explicit objective. The nine cases say how to reach a policy boundary; the critical-signal catalogue (§6.1) says what makes the result worth escalating. Every observed response is screened for those signals, and anything resembling a real secret, credential, PII set or internal topology is handled under the minimum-proof, redaction and retention rules in §9. This layer evaluates the nine cases; it is not a hidden tenth case, and it never reclassifies another owner's bug (SSRF, SQLi, auth bypass) as an access-control finding.

## 3. Assumption audit against the pre-implementation checkout

These observations describe the **pre-implementation baseline**, retained for traceability; §11 states the current behavior.

| Claim to validate | Actual behavior | Planning consequence |
|---|---|---|
| `access-control` is seeded for every `api_like` asset | **Qualified.** `recon/score.py:164–169` first adds `idor-bola` when `id_params` or `{id}` is present; `api_like` adds `access-control` only if `idor-bola` is absent. `INTERNAL` then adds `access-control` regardless. | Describe it as **API-like endpoints without an earlier IDOR seed, plus paths matched by `INTERNAL`**. This is a heuristic, not every actual API. |
| ID-bearing API endpoints receive only `idor-bola` | **Usually, not always.** `INTERNAL` is broad (admin/internal *and* debug, export, import, backup, bulk, etc.); it can add `access-control` to the same endpoint. Later `score.py:223–225` unconditionally adds `idor-bola` for GraphQL/GQL paths, so an API-like GraphQL path without IDs can also have both classes. | At overlapping rows, route the *object-substitution* hypothesis to `hunt-idor`, function/field/entry-path policy to this skill, and deduplicate any shared root cause. Do not pretend the classes are mutually exclusive. |
| `mass-assignment` is seeded on every write endpoint | **Not yet.** `score.py:192–195` currently seeds it for observed **POST/PUT/PATCH**, not DELETE, and does not require `api_like`. A standalone POST form can get the row; a DELETE-only operation currently cannot. | **Proposed change after approval:** seed the class for DELETE as well, including non-API DELETE routes. A row is only a candidate; if no assignable property is established, record the prerequisite gap rather than claim a vulnerability. Unknown-method routes remain unknown. |
| The two classes already have a mapped skill | **No.** `recon/skillmap.py:19–32` maps neither; `tests/test_recon_skills.py:401–402` explicitly expects `mass-assignment` to display `-`. | Mapping, catalog entry, skill file and tests must land together *after approval*. Update the old assertion deliberately, not by weakening the test. |
| `hunt-idor` does not cover tenant headers or GraphQL | **False.** Its `SKILL.md:55–99` covers object references in headers, cookies, GraphQL variables, and cross-tenant object substitution; `references/techniques.md:9–18` covers location, version, method, GraphQL and transport variants. | Do not duplicate A→V object checks in `ac-tenant` or `ac-projection`. Existing object-reference cases stay with `hunt-idor`, even when `score.py` also seeds `access-control`. |
| The field trigger matrix already gives create/edit/spec diffs | **No.** `recon/fields.py:377–409` records captured observation IDs and missing/n-a trigger cells; it does not compare field sets. `module_of` and `infer_trigger` are heuristic. `recon/specs.py` holds declared `spec_fields`, not server acceptance. | Build a context-safe, value-free diff first. Label output `declared`, `sent` and `not observed`; only a controlled before/after result can establish `accepted`. |

A pre-change pure-function check of `applicable_classes` confirmed: a plain API route yielded `access-control`; an ID route yielded `idor-bola`; an internal ID route yielded **both**; `/graphql` with POST yielded **both**, `graphql` and `mass-assignment`; DELETE did **not yet** seed mass assignment; and even a non-API POST did. This check sent no network traffic and created no campaign. DELETE seeding is now implemented (§11).

The `/private/tmp/plan.md` comparison draft says “377 tests” and “every write endpoint”; the latter becomes an **intended future behavior only after the DELETE seeding change**. The prior verified suite checkpoint is **388 tests**; do not treat that as a fresh run for this revision. External source paths, quotations and licenses listed in the tmp draft are leads for a future provenance review, not verified inputs or text to copy into this MIT repository.

## 4. Ownership boundary for `ac-tenant` and other overlaps

**Decision: narrow `ac-tenant`, rather than drop it or deliberately duplicate IDOR.** It covers tenant-scoped *functions and collections without an individual object-reference swap*: e.g. a list or aggregate operation whose captured, attacker-influenceable tenant selector changes which test tenant's results are returned, or a tenant-wide function available to a role that should not have it. Use only supplied A/B tenants and A/B-owned marker data. A signed token claim is **not** a freely editable tenant parameter; test the issued accounts' privileges, and route token-validation defects to the auth owner. If the test requires substituting V's object ID anywhere (including a tenant header that acts as that object's identifier), hand it to `hunt-idor`.

Apply the same root-cause ownership rule elsewhere:

- `ac-role` owns function-level/vertical authorization on an operation without a V-owned object swap. `hunt-idor` owns BOLA/BFLA where the demonstrated boundary is object/identity substitution; link related findings rather than filing duplicates.
- `ac-projection` owns policy differences among access paths to a field or collection (e.g. selection versus sort/filter/expand, or GraphQL field visibility on a readable **A-owned** node). If the decisive proof is a V-owned node/object, `hunt-idor` leads. GraphQL paths may seed both classes; that is a routing decision at the *hypothesis*, not a claim that the seeding is exclusive.
- `ac-surface` owns alternate render/export/bulk paths to a protected function or aggregate dataset. If it requires V's document/invoice ID, `hunt-idor` owns the object-access proof; this skill can record the surface as a linked sibling.
- `ma-privileged-field` owns server acceptance of an unauthorized writable property on a disposable owned record. A subsequent cross-object read/write or ATO is a separately validated chain step, not proof supplied by merely adding a field.

Record the owner chosen, source class row(s), related case IDs and root-cause dedup key in the ledger. Do not silently mark an overlapping coarse coverage row `tested` or `n-a` just because the other skill examined one variant.

## 5. Authorization and target-agnostic workflow

1. Start from written program rules, `scope.json` includes/excludes, mode, methods, rate/time/request budgets, `excluded_bug_classes`, approved execution path and the operator's A/B test accounts. A discovered hostname, old API version, spec `servers[]` URL, alias or redirect never widens scope. `recon check` each intended URL. The default live path is the dedicated visible browser through Burp when connected; a standing campaign plan may independently approve bounded `recon send` or operator-run tooling. Burp/external requests are not enforced by recon's budget and must be manually reserved/reconciled.
2. Build an operation inventory from captured A/B workflows, HAR/Burp imports, JS/routes, provided JSON OpenAPI/Swagger, exact variants and source references. Separate *declared*, *static-referenced*, *inferred sibling* and *captured real request*; none alone proves a backend authorization decision. GraphQL, OData and batch support must be observed or documented before their cases are applicable. `UNKNOWN` method/auth/account/role/tenant/workflow stays unknown.
3. For one protected function/dataset, draw a **sibling-path graph**: identity and role, tenant-scoped function, granted method/override, version, projection/query/resolver, representation/batch, export/report/bulk surface, and write-field shape. Link paths only if they plausibly reach the same policy target; exact origin, path variant, operation selector, method, representation, role, tenant, account and workflow remain distinct test contexts.
4. Establish a legitimate A→A or authorized-role baseline and an independent readback/marker. Change **one** dimension per bounded hypothesis. A negative control must distinguish unauthorized effect from public content, soft-404, cached response, generic 200 error envelope, or a different resource. For a suspected missing-auth flaw, an anonymous request's protected A-owned result plus the authorized baseline and a non-target denial/other control may be appropriate; a “guarded sibling” is useful but not mandatory when no equivalent sibling exists.
5. Stop on 429, lockout, CAPTCHA, unexpected side effects, cap exhaustion or an unavailable approved execution path. Hard bans that no grant lifts: token-claim forgery, credential guessing, enumeration against real users' objects, destructive admin actions, unsupported TRACE/CONNECT, and any out-of-scope host. With an explicit campaign grant and a per-host budget, the following expansions are allowed — one dimension per attempt, each still `recon check`-ed where recon sends it:
   - `method-matrix` — alternate granted methods, `_method` overrides or documented override headers/body fields against a captured operation whose policy may be method-specific.
   - `sibling-expand` — bounded discovery of version, mount, mobile or documentation siblings from a captured route. A sibling found this way is still a hypothesis, never an automatic in-scope request.
   - `representation-fuzz` — content-type swaps, HPP in both orders, duplicate JSON keys, array/object wrapping, multipart/XML twins of a captured request.
   - `id-mutation` — small, bounded mutations of identifiers **you own** (A/B objects and test-owned markers) to learn the scheme or find a weaker sibling; never adjacent IDs belonging to strangers.
   - `read-extraction` — the minimum read-only requests needed to establish exposure: an in-scope debug/actuator/documentation surface, a safe error-triggering payload, or a response already observed to carry a sensitive value. Cloud-metadata fetches are `hunt-ssrf` work, not this skill's; record observed metadata content and hand it over.
   - `write-proof` (optional, opt-in) — create/mutate/delete on disposable owned resources to prove impact, under an explicit method grant, before/after proof and agreed cleanup.

   Write tests—including DELETE—need explicit method grants, disposable A/B-owned resources, before/after proof and agreed cleanup. A DELETE coverage row never authorizes a destructive probe.
6. Replay a candidate with a fresh owned marker/resource and a distinct negative control. Judge the actual protected data/function effect, attacker-reachable preconditions and duplicate root cause. The existing `finding` stages and `chain realism` gate decide reportability; a case event or `recon fact` status/byte predicate never promotes a finding. If the root cause can chain, record the next rung as a new hypothesis with its own grant and parent event rather than stretching this case's evidence.

**Effort proposal (risk-weighted, not uniform):** read-only, low-noise cases (`ac-method`, `ac-version`, `ac-projection`, `ac-transport`) may use the campaign's read-only cap, default eight variants per case/context; `ac-unauth`, `ac-role`, `ac-tenant` and `ac-surface` get one controlled variant per owned resource plus baseline and controls; `ma-privileged-field` and any `write-proof` rung get one attempt per owned resource with before/after readback. Chain rungs spend from the same budget and need their own grant. Any lower campaign cap wins. This is an effort limit, **not** a claim that the endpoint or class has been fully tested; capture which variants remain open, blocked or inconclusive.

## 6. Nine-case ladder (implemented offline case IDs; no live executor)

| Case | Applicability and controlled contrast | Observed proof / handoff |
|---|---|---|
| `ac-unauth` | Captured protected operation: authorized A request versus a no-credential request to the same exact operation and owned resource; distinguish absent from invalid credentials. An unauthenticated in-scope debug/actuator/docs surface is in scope only under a `read-extraction` grant. | A's private marker or protected owned effect appears without required auth; public data/error statuses do not count. JWT/parser flaws → `hunt-auth-bypass`. |
| `ac-role` | Supplied low/high roles on the same non-object function and workflow; test one permitted function or owned state transition at a time. | Lower role obtains a higher-role-only effect, independently read back. A/V object swap → `hunt-idor`; no supplied high role means blocked, not a guessed admin account. |
| `ac-tenant` | **Non-object** tenant-scoped list, aggregate or function; compare issued A/B tenant contexts and a captured tenant selector only if controllable and permitted. | Wrong-tenant **test-owned** marker/function effect with same-shape control. Tenant/object ID substitutions → `hunt-idor`; signed claim manipulation → auth review, not this case. |
| `ac-method` | Same protected owned operation through another granted method, a `method-matrix` override (`_method`, override header/body field), or a documented override channel; compare middleware and handler results. | Alternate method reaches the protected effect while matched baseline/control show the intended policy. `Allow`/OPTIONS is a lead, not permission or proof; unsupported TRACE/CONNECT are not sent. |
| `ac-version` | Current route versus an actually captured/referenced, in-scope old version or mobile API host, or a bounded `sibling-expand` candidate derived from that route. Ungranted inferred `/v1/` siblings stay unrequested leads. | Same owned action/dataset under weaker policy on one version with a rejected/authorized control on the other. No unbounded version guessing or external-host probing. |
| `ac-projection` | When supported: field in selection versus sort/filter/expand or navigation; REST query fields; GraphQL node versus field/resolver, across the same role/tenant and owned records. | Unauthorized protected **owned** field or policy-relevant inference demonstrated with a bounded marker/control. A query count alone or schema/introspection alone is not proof. V-owned object access → `hunt-idor`; SQLi/XXE → those owners. No prefix extraction of real-user data. |
| `ac-transport` | Captured same operation in another actually accepted representation: JSON/form/multipart/XML, OData `$batch` inner operation, GraphQL alias/batch or REST twin; a `representation-fuzz` grant is required for shapes not already captured. One variant per attempt. | The inner/protected owned operation succeeds where same-policy single/normal transport is denied; distinguish parsing from backend authorization. Content-type support, batch availability or a parser error alone is not a finding. CSRF/browser delivery → `hunt-csrf`. |
| `ac-surface` | Same protected dataset/function via list/detail versus export/report/print/download/bulk, only where observed or documented and within scope. | Alternate surface exposes an owned protected field or performs the forbidden owned effect, with an equivalent control and independent readback. Individual V-owned object IDs → `hunt-idor`. |
| `ma-privileged-field` | POST/PUT/PATCH/**DELETE** candidate on a disposable owned record. For DELETE, first establish an observed or documented request-body/parameter shape that can assign a property (for example, a soft-delete option); do not invent one merely because the method was seeded. Compare context-matched captures and spec-declared properties; propose only a security-relevant field tied to an observed schema/response or written feature. | Server **accepted and applied** a property the caller must not control, proven by a separate owned readback and a same-shape control. An absent spec declaration, a sent field, a 200 or deletion alone is not mass assignment. Never alter another user's account or permanent privileged state. |

The first eight are access-control cases; the ninth is mass assignment. Plan cards name case-specific prerequisites, next safe comparison, the existing class owner, scope/method grants, estimated request effort and what evidence is still missing. `negative` is scoped to one exact context and variant; missing captures, denied permission or a late async response are not negatives.

### 6.1 Critical-signal catalogue (impact layer, not a tenth case)

The cases say how to cross a policy boundary; this catalogue says what makes the result worth escalating. Every observed response, capture and artifact is screened against it, and each hit is recorded with its case, context, handling decision and confidence.

| Signal | Examples | Route and handling |
|---|---|---|
| Credentials and secrets | API keys, bearer/session tokens, signing or private keys, passwords, connection strings in responses, JS or debug/config output | Treat as chain fuel and possible critical exposure; do not reuse outside a `token-use` grant; redact values in notes and reports; hash the artifact. |
| PII and regulated data | Email, phone, address, KYC/identity documents, payment identifiers, health data belonging to another context | Minimum marker only; never bulk-download or aggregate; stop at sufficiency; do not retain raw values beyond the evidence minimum. |
| Internal topology | Internal hostnames/IPs, cloud account or project IDs, stack traces, build paths, metadata content | Record as an exposure lead; metadata and internal fetches belong to `hunt-ssrf`; do not probe discovered internal hosts. |
| Access-granting state | Role/admin/tenant flags, invite or reset tokens, MFA state, impersonation handles | Chain fuel under the relevant grant; changing another account's state is never allowed, even with a token, unless the program explicitly permits it. |
| Business-critical aggregates | Full-dataset export, admin reports, billing/usage data, bulk PII counts | `ac-surface`/`ac-projection` territory; measure with test-owned records only; report the mechanism, not a copied dataset. |
| Configuration exposure | `.env`, feature flags, debug consoles, unlisted admin routes in specs, source maps | Pair with `ac-unauth`/`ac-version`; a docs or config disclosure stays a lead until an unauthorized protected effect is shown. |

A critical signal raises **priority, not certainty**: it still needs the case's own baseline and control. A secret in a response proves exposure of that value, not that it is live, privileged, or safe to use. Any use of a recovered credential needs a separate `token-use` grant, stays on the granted target, and stops before lateral movement unless `lateral` is also granted. Hits feed the finding's impact class and the priority queue; they never auto-promote a finding (§9).

## 7. Prerequisite: a safe, multi-sample trigger diff

`FieldLedger.matrix()` answers *whether* list/search/filter/create/edit/bulk/export/sort triggers were captured. The implemented offline companion `FieldLedger.diff()` additionally:

- Groups captures by a justified common origin, resource/function, version, account/role/tenant/workflow and representation; preserves each exact method and operation on its own row. It compares *different* create/edit operations only when they act on the same owned resource and policy context, and displays when they are **not comparable**. The current `module_of()` and `infer_trigger()` heuristics are hints, not equivalence proof.
- Calculates per-trigger sets of **sent** query/body/header/cookie names; contrasts create versus edit and list versus export/bulk against each operation's own method-matched `spec_fields` as **declared**. Track captured DELETE fields separately by exact operation, since the current eight-trigger matrix has no DELETE cell. Label `sent-not-declared`, `declared-not-observed` and `trigger-exclusive` as leads. Do not call them `accepted` or `required/optional` from one sample. Repeated presence is still not a server validation rule.
- Keeps source observation IDs and import provenance, truncation/unsupported counts and the A/B context. Avoid full raw values, secret fields and pooled role/tenant variants. An independently observed readback is needed to upgrade `sent` to `accepted` for mass assignment.
- Does not change the existing eight-trigger `full` claim into authorization-test completeness. A complete parameter-shape matrix can coexist with untested `ac-projection` or `ma-privileged-field` cases; report those gaps separately.

This shared infrastructure landed before the skill ledger; CSRF/SSTI/field-ledger regressions passed. No extra HTTP requests are made by the diff.

## 8. Approved implementation design (historical proposal; see §11 for actual state)

| Piece | Approved change | Boundary |
|---|---|---|
| `recon/fields.py` | Context-safe multi-sample diff above | Offline, value-free, separate captured and spec sources. |
| `recon/score.py` | After approval, seed `mass-assignment` for DELETE alongside POST/PUT/PATCH without changing the existing `csrf` write-method rule | Seeding means *candidate only*. Bodyless DELETE remains an open applicability question; no automatic payload generation or execution. |
| `recon/campaign.py` | Add the fail-closed `authz` grant section below to the campaign schema and `scope_template`, with per-host budgets | Absent grant means refused; unknown values refuse the section. No grant widens scope or method allowance. |
| `recon/authz.py` (new *after* approval) | Event-sourced target/path/context/case ledger with `sync`, `plan`, `record`, `status`, `verify`, plus chain rungs and impact classes | No HTTP client, browser, scanner or subprocess. Never use a credential or promote a finding. |
| `recon/cli.py` | Future `recon authz` subcommands `sync`, `plan`, `record`, `status`, `verify` | Every command reports `executed: false`; no `run` or `scan` verb. |
| `.claude/skills/hunt-access-control/` (new *after* approval) | Skill, permission-scoped probe playbooks, critical-signal catalogue and case/evidence/source references with scoped browser/Burp workflow | The engine names the skill but never loads or executes it. A probe playbook describes an allowed family; it never grants one. External excerpts require verified provenance/licensing before adaptation. |
| `recon/skillmap.py`, `catalog.py`, `report.py`, prompts | Map exactly the two classes, inventory actual capabilities, show per-path/context open and stale cases plus coarse-row conflicts | Do not seed a new `api-misconfig` class; do not treat a coarse `cov tested` as full case coverage. |
| `tests/test_recon_authz.py`, relevant existing tests (new *after* approval) | Ledger, diff, CLI, routing, report, owned-loopback and negative-control regressions | Update `test_recon_skills.py`'s currently unmapped mass-assignment assertion, not remove skill/catalog parity checks. |
| `recon/findings.py`, `chain.py` | Reuse existing access-control and mass-assignment hints and realism gate first | Do not add speculative chain rows or unrelated `known-cve` seeding in this build. |

**Ledger key and tables (conceptual, subject to review):**

```text
authz_targets: id, endpoint_asset_id, origin, exact_route_variant, method,
               protocol, operation_selector, protected_function_or_dataset,
               discovery_basis, source_refs
authz_paths:   id, target_id, path_kind, path_detail, evidence_basis,
               equivalent_policy_basis
authz_contexts:id, path_id, representation, auth_mechanism,
               account, role, tenant, ownership, workflow, version,
               capture_basis, facet_hashes
authz_events:  id, context_id, case_id, variant, state, policy_sha256,
               relevant_facet_hashes, comparison_refs, declared_request_count,
               proof_basis, overlap_owner, grant_ref, chain_parent_event_id,
               impact_class, note, created
authz_artifacts: event_id, role, campaign_relative_path, sha256, bytes,
                 source_kind, source_ref, captured_at
```

Use exact URL/method/operation/context identity rather than a host-wide auth profile. Preserve unknown versus anonymous, source provenance and A/B separation. Avoid SQLite NULL uniqueness surprises. Bind events to scope/policy and relevant source/context hashes; reopen dependent cases when those facets change, while retaining stale history. Verify bounded, campaign-local artifacts and distinct baseline/test/control/effect roles as applicable. Native response IDs must refer to actual `recon send` captures; Burp IDs are labeled external references, never fabricated native facts. Hash integrity is not causal validation. Reports show totals and truncation.

No `api_misconfig` class or broad scanner is proposed, but the aggressive probes and chain rungs do require a **small, fail-closed `authz` grant section**, parallel to `ssti.depth_grants`:

```json
"authz": {
  "probe_grants": ["method-matrix", "sibling-expand", "representation-fuzz",
                   "id-mutation", "read-extraction"],
  "chain_grants": ["token-use", "lateral"],
  "probe_budget": {"requests": 40, "per_host": 15}
}
```

Absent keys mean refused; `write-proof` and `persistence` are refused unless explicitly listed; any unlisted family or unknown value refuses the section rather than widening it. Those numbers are illustrative, not defaults — each campaign sets its own ceiling. Scope, `policy.mode`, `allowed_methods`, rate limits, exclusions and the private standing execution plan still apply on top. An offline plan is not authorization; a two-tenant, batch, external-tool or `write-proof` test needs the relevant written allowance and a bounded per-case plan. If an enforcement adapter is desired later, design it separately with atomic shared budgets and scope/redirect/egress checks.

## 9. Proof pairing, coverage and reporting

A positive event needs an **authorized baseline**, a controlled unauthorized attempt and a **distinct negative control** that rules out another explanation, plus independent owned-state/read evidence for writes, field acceptance and asynchronous results. A guarded sibling is particularly valuable when the same policy should apply, but a single unguarded endpoint can also be proven if its required boundary and effect are clear. Check exact request shape, actor, token *mechanism*, account, tenant, method, response completeness, marker ownership, time and cache behavior. A response status or `factcheck.py` byte/header predicate only supports its narrow recorded fact.

Persist `attempted`, `observed`, `negative`, `blocked`, `inconclusive`, `n-a` and derived `stale` at the context × case × variant level. `n-a` needs a verified missing prerequisite; a spec that does not mention a route is not enough. The caps in §5 are effort limits, never endpoint-wide negative coverage. When both `access-control` and `idor-bola` are seeded, show the chosen owner and unresolved work for each row. Deduplicate a shared root cause across entry points in reporting; split findings only if policy boundary, fix or impact is independently distinct, and justify that split.

A chain rung is proven like any other case: parent event, fresh owned marker, distinct negative control. Observing a token, an internal address or an admin flag is a **lead**; using it needs its own grant and its own event, and a parent's severity never substitutes for the rung's evidence. Critical-signal handling is part of evidence: redact secrets and PII in stored notes and reports, keep a minimum marker plus hash rather than a copied dataset or another user's record, and label a value `observed` rather than `live` until a granted control demonstrates liveness. Deleting or withholding an artifact is a scope/retention decision, never a way to erase an inconvenient result.

Record the test basis (`executed-live`, `executed-owned-lab`, `static-unexecuted`) honestly. A measured fraction is appropriate only over an explicit **owned/authorized sample**; do not enumerate production records to manufacture a denominator. Finding progression stays `lead → confirmed` (replay + distinct control) `→ impact-proven` (actual effect and realism) `→ reported` under program rules. Neither this ledger nor scanner output promotes a finding automatically.

## 10. Milestones and acceptance tests

| Phase | Deliverable after approval | Gate |
|---|---|---|
| **P0 — scope and provenance review** | Confirm the nine cases, option-1 `ac-tenant` boundary, class ownership, the `authz` grant matrix and fail-closed defaults, the critical-signal catalogue, the optional `write-proof` policy, source/license checks and campaign permissions | No new class or broad scanner; an ungranted probe family stays blocked; record any target-specific blockers. |
| **P1 — offline diff** | Implement the context-safe create/edit/spec and trigger-exclusive field view | Two unrelated tenants or methods never merge; `sent-not-declared` is not `accepted`; no network. |
| **P2 — seeding, grants and offline ledger** | Add DELETE to `mass-assignment` candidate seeding; parse the fail-closed `authz` grants; add target/path/context schema, idempotent sync, case applicability, blockers, readiness and the impact-ranked next actions | POST/PUT/PATCH/DELETE rows seed as intended, including non-API DELETE; a bodyless DELETE is not automatically an observed or negative mass-assignment case. An ungranted probe family reports `blocked`, not `n-a`. IDOR overlaps route correctly; GraphQL/internal exceptions are tested; unknown contexts do not become negatives. |
| **P3 — evidence** | Add record/verify with hash-bound local artifacts, policy/facet staleness, proof-role checks, chain-parent and impact-class binding, and redaction checks | A 200 without an owned marker/effect cannot be `observed`; a chain rung without its parent event cannot be `observed`; an unredacted secret or copied dataset fails verification; missing guarded sibling is not a blanket refusal; tampering invalidates proof. |
| **P4 — wiring and skill** | Add `hunt-access-control`, map the two existing classes, catalog/CLI/report/prompt docs, the permission-scoped probe playbooks, the critical-signal catalogue and evals | Skill/catalog parity, coverage row routing, playbooks mention only grantable families, no new `api-misconfig` class, no automatic finding promotion. |
| **P5 — owned labs and regression** | Two-account, two-tenant local fixtures: guarded/unguarded function, OData-like projection/filter, GraphQL field, version/transport/export sibling, method-override, representation-fuzz, mass-assignment accepted-versus-ignored field, a synthetic secret-in-response fixture and one chain rung | Positive and near-miss controls pass; method/scope/budget and **grant** denials hold (absent `sibling-expand`/`write-proof` refuses); minimum-proof redaction holds; existing full suite remains green. |
| **P6 — supervised authorized pilot** | Only after another operator decision: a small campaign with written scope, A/B accounts and approved browser/Burp plan | Reconcile external request counts, false positives, cleanup, root-cause dedup and reportability; the plan itself grants no live testing. |

Include skill-behavior evals for: a 200 without effect/negative control; a module with untested sort/filter/expand positions; a create/edit/spec diff mistaken for field acceptance; GraphQL dual seeding; a DELETE-only route seeded but lacking evidence of assignable fields; `ac-tenant` incorrectly claiming an object-ID case; an ungranted probe family that must refuse and record `blocked`; a secret in a response treated as a live credential; a chain rung recorded without its parent event; bulk PII copied instead of a minimum marker; and a read-only cap exceeded without a fresh grant. Optional source-pack/model review is a separate, operator-approved workflow; no unverified model IDs, third-party text or build pipeline are prerequisites to this plan.

## 11. Implementation checkpoint (2026-11-14)

- **P0–P4 implemented:** `recon/fields.py` value-free, context-separated `diff`; `recon/score.py` DELETE mass-assignment candidate seeding; `recon/campaign.py` fail-closed `authz` grants and declared request limits; `recon/authz.py` offline sync/plan/record/status/verify with exact operation/context keys, GraphQL selectors, chain-parent/impact/root grouping, hash-bound artifacts, policy/context staleness and coarse conflicts; CLI, catalog, report, prompt, skill and references wired. `access-control`/`mass-assignment` route to `hunt-access-control`; `idor-bola` stays `hunt-idor`.
- **P5 owned-lab workflow validated:** actual loopback requests were imported through HAR, then `authz sync/plan/record/status/verify` handled nine case families across anonymous/role/tenant functions, OData-like filter/selection, GraphQL field policy, method override, form/batch transport, version/export siblings, synthetic secret and fresh-marker token-use chain. Separate controls distinguish guarded/unguarded behavior and applied-versus-ignored mass assignment. Exact path/query shapes and GraphQL selectors remain separate; DELETE field-gap/readback, grant/method/budget denials, stale attempts, negative-only coverage and artifact tampering have regressions. The complete `.venv` suite passes **422 tests** at this checkpoint. These are intentionally small **owned simulations**, not protocol-complete testing of every server or automatic vulnerability validation. Skill-behavior/model-run evals remain unrun; static skill/catalog routing and case safety regressions passed.
- **Remaining limitations:** the ledger checks structural proof roles, hashes, obvious raw-secret signatures and a redaction marker, **not** actual server-side causality or general-purpose PII/secret scanning. Impact ranking uses path/write heuristics and operator annotations, not a severity verdict. Declared Burp/external request counts are not reconciled with the native network budget automatically; the operator must enforce a single shared ceiling. A sent field does not prove it was accepted. All live operation grants remain separately subject to written rules, method/scope checks and the standing execution plan.
- **P6 not run:** no target, campaign, supplied A/B identities, connected dedicated browser or target-specific written rules were provided. A supervised live pilot needs a separate operator decision. No real target was contacted or finding promoted by this implementation.
