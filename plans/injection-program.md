# BugVault Injection Program — Field Ledger, WAF Profiles, Model-Routed Payloads, Blind XSS, Chains

Plan date: 2026-11-13. Status: planned, not started. Everything below extends the
existing authorized-testing model (scope in code, test accounts, marker proofs,
negative controls, program-allowance gates). Those gates are design constraints,
not limitations on depth: every chain listed (XSS→ATO, blind XSS→admin,
HTMLi→token→ATO, SQLi→admin, SQLi→data, SQLi/SSTI→RCE) is in scope of this plan
and terminates in a reportable, replay-proven finding.

---

## 0. Current state (what exists today)

| Piece | State |
|---|---|
| Input census | `recon inputs` (read-only): merges HAR observations + attrs, locations, accounts, sensitive flags, stored-probe receipts. Known gaps stated: headers/cookies, hidden params |
| HAR JSON depth | `har.py _flatten` = 2 levels, first array element only |
| Forms | Collected on jsharvest-crawled pages (`<form>` inputs only, nothing outside forms) |
| Burp history | Not importable; live MCP reads only |
| OpenAPI / GraphQL args | GraphQL paths seed `graphql` class; argument names from JS only; no OpenAPI parsing |
| Coverage granularity | Coarse `(asset_id, bug_class)` rows; no per-field state |
| WAF knowledge | Probe-ladder methodology in hunt-xss/hunt-sqli prose; no per-host persisted profile |
| Payload design | Skill prose; no context packet, no model attribution record |
| Blind XSS | Methodology only; no evidence matching (SSRF correlator exists and is generalizable) |
| Chains | findings.py hints + chain.py templates cover XSS→ATO/SQLi-adjacent partially; no html-injection or ssti classes |
| Runtime mocks | `synthetic-ui-mapping` (runtime.py) already loads the real app with API calls answered by mocks; **no** auth/permission-check stubbing at page start, **no** form→request-body tracing, **no** pre-encryption body hooks |
| Completeness gate | No module × trigger matrix; nothing forbids a full-coverage claim before all workflow shapes are captured |
| Impact realism | Validator checks harm/replay but has no explicit attacker-reachability, precondition-realism or downstream-blocker screen |

## 1. Fix 1 — Field ledger (the unit of coverage changes)

### 1a. Field discovery fixes (engine)

- **Full-depth JSON** (`har.py`): replace `_flatten` with bounded recursion:
  depth ≤ 6, arrays as `items[].leaf` and `items[0]` both recorded (existence of
  array-wrapping matters for bypass variants), ≤ 200 leaves/record, leaf names
  kept as dotted paths. Same change in the OpenAPI parser (1c).
- **Forms on all pages** (`active.py`): jsharvest already walks crawled pages;
  verify every visited page's forms are ingested (not only entry pages), and
  record `form action`, `method`, `enctype` per input for multipart detection.
- **Inputs outside forms** (`extract.py` HTMLParser): collect standalone
  named elements — `input/select/textarea` without a `<form>` ancestor,
  `contenteditable` elements, rich-editor containers (`data-testid`,
  `aria-label`, `ng-model`, `v-model`, `name` attributes). Label text (nearest
  preceding label/placeholder) is recorded so the ledger reads
  `firstName (label "First name")`, not a bare DOM name.
- **Request-body keys from JS** (`extract.py` JS parser): existing fetch/axios
  extraction gains body-key extraction from object literals passed to
  `.post(`/`put(`/`patch(` and `body:` options (names only, bounded).
- **Burp history import** (`recon/ingest.py` + new `import-burp` command):
  accept (a) Burp's "Save items" JSON/XML export and (b) raw HTTP request
  files; parse to the same observation shape as HAR (names only, ID-like values
  kept, header/cookie **names** now also captured with values dropped — closes
  the census gap honestly). Live MCP history stays read-only and bounded.
- **OpenAPI** (`active.py` wellknown job): fetch in-scope
  `/openapi.json|yaml`, `/swagger.json` (GET, passive-safe), parse
  `paths → method → parameters + requestBody schema` → field rows with
  `location` from the spec (`query/path/header/body`) and dotted schema paths.
- **GraphQL** (`extract.py`): argument names from JS-extracted queries/mutations
  (already partially there — extend to variables objects); introspection-based
  schema args only when a POST grant exists; noted as blocked otherwise.
- **Runtime deep-pass — stub the auth/permission gates at page start**
  (`runtime.py`, extends `synthetic-ui-mapping`): statically identify the
  bundle's login-gate / permission-check functions (from jsharvest symbols),
  then in the mocked local render inject stubs at document-start so every
  gated screen (admin, staff, tenant) renders, and harvest forms/fields/labels
  and attempted API calls from each screen. Honesty constraints that stay:
  this renders **client-side only** against mocked APIs — it discovers surface
  (fields, endpoints, request shapes), it never grants backend access, and
  server-side authorization still governs every real request. The runtime's
  existing "synthetic ≠ backend access" rule is unchanged; discovered admin
  screens become ledger rows to test properly, not findings.
- **Submit-handler → request-body tracing** (`runtime.py` + `fields sync`):
  for every rendered form, dispatch the submit path with mocks answering, hook
  the outgoing fetch/XHR, and map each input name → exact JSON path / form key
  in the body the API receives. This gives the ledger's `location` column
  ground truth instead of inference, including nested paths and array-wrapped
  fields. Bound: one dispatch per form, mock responses only.
- **Pre-encryption body hooks** (two surfaces, both operator-owned): (a) in
  the mocked runtime, statically locate the bundle's encrypt/sign functions
  and log plaintext bodies before encryption; (b) an operator-run DevTools
  snippet for the **dedicated browser on the operator's own test session**,
  hooking the same entry points, exportable to the same import format as
  `import-burp`. This is what makes canary markers and field tracing work on
  apps whose request bodies are client-encrypted — the marker must exist in
  the pre-encryption plaintext to be traceable. Never applied to any session
  other than the operator's test accounts.

### 1b. Field ledger store + CLI (`recon/fields.py`, new)

Schema (additive, `CREATE TABLE IF NOT EXISTS` — consistent with ssrf/chain):

```sql
CREATE TABLE IF NOT EXISTS field_ledger(
  id INTEGER PRIMARY KEY, endpoint_id INTEGER NOT NULL REFERENCES assets(id),
  method TEXT NOT NULL, location TEXT NOT NULL,        -- query|form|json|multipart|header|cookie|path
  field TEXT NOT NULL, account TEXT, role TEXT, tenant TEXT, workflow TEXT,
  case_id TEXT NOT NULL,                                -- e.g. xss-stored, sqli-boolean
  state TEXT NOT NULL,                                  -- untested|probed|mapped|observed|negative|blocked|inconclusive|n-a
  note TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '',  -- payload author attribution
  created TEXT NOT NULL, updated TEXT NOT NULL,
  UNIQUE(endpoint_id, method, location, field, account, case_id));
CREATE TABLE IF NOT EXISTS canary_events(
  id INTEGER PRIMARY KEY, marker TEXT NOT NULL, endpoint_id INTEGER REFERENCES assets(id),
  surface TEXT NOT NULL,        -- same-response|other-endpoint|admin-view|staff-view|email|export-csv|export-pdf|dom
  encoding TEXT NOT NULL,       -- raw|html-entity|url|unicode|base64|stripped|truncated
  request_id INTEGER, source TEXT NOT NULL, first_seen TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', UNIQUE(marker, surface, encoding, source));
```

Commands (all offline planners/records; execution stays browser/Burp):

```
recon fields sync  <campaign> --asset-id N     # rebuild ledger rows from every discovery source above
recon fields show  <campaign> --asset-id N [--case C] [--state S]
recon fields canary <campaign> --asset-id N --field F   # plan the per-field marker submission (marker minted, workflow named)
recon fields trace <campaign> --marker M      # search stored requests/responses (+Burp reads) for the marker; record canary_events
recon fields record <campaign> ... --state --note [--model] # outcome + payload-author attribution
```

Coverage joins: `recon inputs` gains a `ledger_state` column per field;
`coverage.md` gains a per-field section for ledgers endpoints. Coarse
`(asset_id, bug_class)` coverage stays for backward compatibility.

### 1c. Canary pass and the propagation map

Per field: submit one unique marker (`bv_<8 rand>`, per-field so attribution is
unambiguous), through the real save/preview workflow in the dedicated browser.
Then `fields trace` searches: stored native responses, later HAR re-imports,
Burp history reads (bounded, operator-approved), and export/email surfaces the
program exposes to your own test account. Each hit becomes a `canary_event`
with surface + encoding. The map answers, per field: where does it land, how is
it encoded in each place, does it reach admin/staff views or exports — which is
exactly the input the XSS context table and the stored/blind variants need.
Stored/second-order surfaces are found by tracing across time (trace re-runs
after each import), not by guessing.

### 1d. Parameter trigger matrix (coverage-completeness gate)

Coverage is not claimable per endpoint in isolation — the same field behaves
differently per workflow shape. Derived view over the ledger:

```
module (endpoint family) × trigger ∈ {list, search, filter, create, edit,
bulk, export, sort}  → captured requests compared?
```

- Built from HAR/Burp `workflow_state` labels plus the runtime deep-pass
  (each rendered screen's data operations are tagged with their trigger).
- `fields show` and `coverage.md` render the matrix per module with
  captured/missing cells; a module's parameter coverage state is
  `incomplete` until every **applicable** trigger has at least one compared
  request (some modules legitimately have no bulk/export — recorded as `n-a`
  with a reason, not silently missing).
- **Engine-enforced honesty rule**: `fields record --state observed` on a
  module whose matrix is incomplete also stamps the module
  `coverage_claim: partial`; any report-level "full parameter coverage"
  wording is rejected by the report writer while cells are missing. Claiming
  full coverage before the matrix is complete is forbidden by the tool, not
  just by discipline.
- Comparing the captured shapes is where the depth comes from: the same field
  with different types/encodings across triggers (search numeric vs edit
  string; export adding `format`/`sort`) is exactly where validation gaps and
  second-order sinks hide.

## 2. Fix 2 — WAF profile per host (`recon/waf.py`, new)

```sql
CREATE TABLE IF NOT EXISTS waf_profiles(
  host TEXT PRIMARY KEY, signature TEXT NOT NULL,      -- json: {kind: status|template|header|reset|challenge|silent-strip, status, header_set_sha, template_sha, notes}
  elements TEXT NOT NULL,                              -- json: [{element, alone, pairs[], location, content_type, outcome}]
  updated TEXT NOT NULL);
```

- **Block signature capture**: `recon waf observe <campaign> --host H` records
  the features of one blocked response vs one passing baseline (status, header
  set hash, body template hash, connection reset, challenge redirect,
  silent-strip = baseline passes while the element is absent on output —
  distinguished from an application error by the error's app-correlated shape).
- **Element table**: `recon waf plan --host H` emits the probe sequence —
  single elements first (one special char, a tag name, an event-handler word,
  a quote, a SQL keyword, a comment sequence), then pairs — each probe carrying
  its own marker. `recon waf record` stores allowed/blocked **per location and
  content type** (query vs JSON body vs form vs multipart vs header), because
  profiles routinely differ per parser path.
- Skills consume the profile: the probe ladder in hunt-xss/hunt-sqli reads
  `waf_profiles.elements` instead of starting cold; the payload context packet
  (§3) embeds the surviving-characters set derived from it.

## 3. Payload design: context packets + model attribution

- **Packet** (`recon payload context <campaign> --asset-id N --field F --case C`):
  JSON {field, location, context_map (from canary events), surviving_chars,
  blocked_elements (from waf profile), db_fingerprint (from sqli error proofs,
  when present), csp (from stored responses), method_grants, sink_surfaces,
  waf_ref, canary_ref}. Completeness validator rejects a packet with any empty
  key — the model-routing.md §6-style check, made executable.
- **Attribution**: `payload_events(id, packet_sha256, model, provider, created,
  note)`; `fields record --model` stamps the ledger row. When the payload-model
  gateway exists (DeepSeek primary per docs/model-routing.md), packets flow
  through it and the §5-style audit (requested vs actual model) lands here;
  until then the ledger's `model` column records who wrote each payload by hand.
- **Division of labor stays exactly as agreed**: session model plans (ledger,
  next field × case from canary map + WAF profile), payload model designs from
  the packet, you execute in the dedicated browser through Burp (Burp MCP may
  prepare Repeater tabs; it cannot run attacks — that stays manual), and a
  validator from a different model family checks evidence: XSS = proof the
  script executed in the browser (DOM/screenshot marker, not body reflection);
  SQLi = replayed true/false pair + negative control, bound via `fact check`.

## 4. Blind XSS matching on the SSRF callback code

Extract `recon/ssrf.py`'s bundle validation (marker binding, host grants, time
window, event normalization, duplicate/conflict rules) into a shared
`recon/callbacks.py`; SSRF and a new blind-XSS bundle share it. Blind-XSS
events: origin `browser-exec`, evidence = the marker observed in the executing
surface (your second test account, or a staff surface the program's blind-XSS
allowance covers), artifact = the capture of that surface. Host grants reuse
`ssrf.callback_hosts` (or a sibling `xss.callback_hosts`).

## 5. Classes and chains

- `score.py`: new `html-injection` class (structure-injection candidates:
  content/bio/description/html fields, `text/html` write endpoints) and `ssti`
  class (template-ish params: template/tpl/theme/lang/format on render/export
  surfaces, Jinja/`${}`/`<%` markers in error bodies).
- `skillmap.py`: `html-injection → hunt-xss`, `ssti → hunt-sqli` (SSTI lands
  initially as a validation/parser cousin; promote to `hunt-ssti` only when a
  real surface class emerges from campaigns).
- `findings.py` CHAIN_HINTS additions: `(html-injection, ato)` token-leak path,
  `(sqli, ato)` login bypass, `(ssti, access-control)` code-exec equivalent,
  `(xss, access-control)` admin surface.
- `chain.py` STEP_CHAINS additions:
  `xss-admin-ato` (xss → access-control → ato),
  `htmli-token-ato` (html-injection → info-disclosure → ato),
  `sql-authbypass-admin` (sqli → ato → access-control),
  `ssti-exec` (ssti → access-control).
  Stacked/write/RCE-adjacent terminal steps inherit the same program-allowance
  gating hunt-sqli/hunt-ssrf already use (`depth_grants`-style), which is what
  makes the RCE-class chain reportable rather than an incident.

## 6. Validator and skill updates

- `validator.md`: XSS evidence standard = browser execution proof; SQLi =
  replayed triple; blind XSS = correlated surface capture via callbacks.py.
- **Realism gate — three mandatory questions on every impact/chain claim**,
  answered with evidence before `impact-proven`/`reported`:
  1. **Can a real attacker reach it?** The surface must be reachable by an
     external attacker under the program's threat model — not only from the
     operator's authenticated test session, internal network position, or a
     synthetic render. This is exactly the check that catches client-side
     auth-stub renders: a screen that renders in the mocked runtime proves
     surface, and if the API behind it still enforces authorization, the
     "admin access" claim dies here.
  2. **Are the preconditions realistic?** Every assumed capability the chain
     needs (a token the attacker can't obtain, a header the browser never
     sends, victim interaction the program's users won't perform, a role the
     attacker cannot hold) is listed and either demonstrated or the chain is
     downgraded to conditional/hypothetical and parked.
  3. **Does something later block the impact?** Check the layers after the
     last proven edge: CSP/script-nonces on the XSS surface, server-side
     authorization on the "admin" object, output encoding at the actual sink,
     credential permissions (the leaked key's actual policy), rate limits and
     WAF behavior on the chained request. A blocked terminal layer makes the
     chain a partial — recorded with the blocker named, never reported as
     full impact.
  Recorded as a `realism` block in the impact artifact and surfaced in
  `chain status` (a chain whose frontier step fails a question is parked with
  the failing question named).
- hunt-xss / hunt-sqli: replace cold probe-ladder prose with ledger + WAF
  profile + context-packet references; add the canary-map context table step
  and the trigger-matrix completeness check before any negative verdict.

## 7. Build order and test matrix

| Phase | Contents | Tests | Status (2026-11-13, branch `recon-engine`) |
|---|---|---|---|
| 1 | Field discovery (full-depth JSON, all-page forms, standalone inputs, JS body keys, Burp import, OpenAPI/GraphQL args, runtime deep-pass with auth stubs, submit-handler→body tracing, pre-encryption hooks) + field_ledger/canary_events + `fields` CLI + per-field coverage join + trigger matrix + completeness gate | Unit: discovery shapes at depth, label capture, Burp export fixtures, ledger uniqueness/staleness, trigger-matrix gate rejecting full-coverage claims with missing cells; owned-loopback: echo app with nested JSON + standalone inputs; mocked-runtime lab: gated screen renders under stubs and its form fields map to exact body paths; census/ledger join | Built + unit-tested. Runtime deep-pass (auth-stub rendering, submit-handler→body tracing, pre-encryption hooks) **deferred**; groundwork: `auth_gates`/`crypto_entrypoints` in `recon/extract.py`. Owned-loopback / mocked-runtime labs need a live campaign + browser/Burp |
| 2 | WAF profiles (schema, observe/plan/record) | Owned-loopback: configurable toy WAF middleware (block by element set, silent-strip mode, fake 403 template) → profile builder classifies all three signatures correctly | Built + unit-tested (classify order incl. silent-strip/header promotion, bounded plan, per-location element table); toy-WAF loopback pending live campaign |
| 3 | Context packets + payload_events + completeness validator | Unit: packet build/reject paths, attribution stamps; model-routing.md cross-refs | Built + unit-tested (packet refuses incomplete context; stable core hash; `payload_events` attribution incl. DeepSeek V4.1 Flash ledger records) |
| 4 | callbacks.py extraction (SSRF refactor, no behavior change) + blind-XSS bundle + chains + classes + realism-gate block in chain status | SSRF suite must stay green unchanged; blind-XSS bundle tests mirrored on the SSRF correlator tests; chain tests for the four new templates incl. a parked chain whose frontier fails realism question 1 or 3; score tests for new classes | Built + unit-tested (SSRF suite green on shared `callbacks.py`; blind bundle shares validation rules; 4 chain templates + realism gate parks completed chains with failing questions named) |
| 5 | Skill/prompt/docs updates + text-only skill evals (iteration-2 for hunt-xss/hunt-sqli) + both Python suites + git diff --check | 25+ new tests expected; eval artifacts under .recon/skill-evals/ | **Partial**: skill/prompt/doc updates done + suite re-verified (327 tests green in `.venv` and system Python, +41 over baseline; `git diff --check` clean). Text-only skill evals iteration-2 for hunt-xss/hunt-sqli pending (artifacts under `.recon/skill-evals/`) |

Phase status notes (2026-11-13):

- All new tests are unit-level and offline, per §8; owned-loopback and
  mocked-runtime proofs still require a configured campaign and the dedicated
  browser/Burp path (`vault/10-Campaigns/` still empty) — unchanged blocker.
- Schema is additive only; no old-row migration was needed.
- Deferred follow-ups: runtime deep-pass (phase 1), OpenAPI in-scope fetch
  wiring (spec import stays offline by design), text-only skill evals
  iteration-2.

Risks: additive-only schema (no migration of old rows); Burp export format
pinning (fixture first, like other ingest adapters); canary false positives
(8+ char high-entropy markers, word-boundary matching, per-field uniqueness);
trace searches bounded (LIKE scans over stored responses with caps).

## 8. Explicitly kept (design constraints, not TODOs)

Program-allowance gates on write/RCE-class chain steps; test-account-only
stored/blind payload observation (staff surfaces only where the program allows
blind XSS); no dumping other users' data (banner/one-test-record proofs);
no destructive statements; rate limits respected; scanners only by explicit
operator exception; live execution only through the dedicated browser + Burp.
These are the compliance layer that makes every chain above submittable.

---

## 9. CSRF hunting program (next hunt build, 2026-11-13)

CSRF becomes an **action-and-context hunt**, not a field checklist. The unit of
coverage is a state-changing action (including fieldless actions and GET
mutations) observed under an exact host/route/method/representation/auth context,
exercised from a realistic browser initiator origin. The engine plans and records
offline; the dedicated browser through Burp performs the cross-origin exercise.

### 9a. Source selections

| Source | Snapshot | Take | Do not import |
|---|---|---|---|
| HackTricks fork (`b4rdia/HackTricks`) | commit `9d61d9142c350c1f6188ffb3c5e6e34407cf8438`, 2023-01-15; CC BY-NC 4.0 | Token omission/substitution/cookie-pair prerequisites, POST→GET and override variants, content-type boundaries, Referer/Origin checks | Flash/ActiveX and malformed-form examples; copying prose/tables/code (non-commercial licence) |
| mind-hunt `hunt-csrf` (local Downloads) | SHA-256 `2f224f4c364183f67442e2bc6c07660adff0e481dd038c135f077a50f5c7d660`; MIT | Session workflow, crown-jewel action ranking, sibling-origin delivery, GraphQL, client-side CSRF, account linking, BFF and SignalR branches | Its token-stability, missing-SameSite, HTTP-200/WS-101 and static-header verdicts; arsenal CSRF templates are absent |
| BugBountySkills `KNOWLEDGE_BASE/CSRF` | commit `0accf5fdc71ec7f03273aebb99268a8609f8dfd4`, 2026-04-25; MIT | `reports-index.md` as a lead index; methodology prompts for JS routes, authenticated boundaries and integrations | Generic payload/bypass templates that confuse CSRF with injection/reflection; unverified corpus totals |

Case cards are **independently authored** from concepts, with per-source
provenance in `.claude/skills/hunt-csrf/references/sources.md` (path, commit/hash,
retrieval date, selected sections, corrections, licence). HackTricks attribution
does not remove CC BY-NC restrictions, so its wording/tables are not copied.

### 9b. Groundwork today and the deltas the hunt needs

| Existing | Delta |
|---|---|
| `recon/score.py:187` seeds `csrf` only for POST/PUT/PATCH/DELETE | Add GET/fieldless write hints, spec-declared operations and form actions |
| `recon/fields.py:121` has one `csrf-state` case | Add the action/context ledger; keep `csrf-state` as a coarse link only |
| `recon/active.py:354` turns forms into endpoints | Promote form action/method/enctype into the action inventory |
| HAR drops headers/bodies; Burp keeps names only | Add privacy-preserving cookie/header metadata sidecars (attributes and presence, never token/header values) |
| Module trigger matrix pools matching paths across origins | Host-specific action keys; no pooling across scheme/host/port |
| Generic “3 attempts then tested” per endpoint | Attempt accounting per action × case × context |
| No `hunt-csrf`, no skillmap entry | New skill + `skillmap`/`catalog`/prompt wiring |
| No browser harness for same-site vs cross-site | Opt-in owned two-origin loopback lab |

### 9c. Architecture — `recon/csrf.py` (new, offline only)

Append-only records, reusing operations/provenance and the SSRF artifact pattern:

- `csrf_actions` — logical business/identity transition; fieldless actions are
  first-class; static/spec declarations stay distinct from captured behaviour.
- `csrf_contexts` — campaign; scheme/full host/effective port; exact route and
  action selector; wire/effective method and accepted override; MIME/representation;
  auth mechanism; account/session alias, role, tenant, ownership, workflow; request
  shape. GraphQL adds operation/document/persisted-query/batch identity; WebSocket
  adds hub/transport/message action.
- Initiator context — separate initiator and top-level origins, schemeful-site
  relationship, delivery mode (navigation/form/frame/subresource/fetch/WS), browser
  engine/build, credential mode and interaction. Same-site is not same-origin.
- `csrf_case_events` — case family, attempt kind, observed vs asserted metadata,
  token locations/design, cookie attributes, Origin/Referer/Fetch-Metadata,
  preflight/CORS/redirects, state/identity readback, external tool references,
  request/connection/message counts, private artifact hashes.

Canonical snapshots cover request-builder/auth/defense/representation changes and
exclude rotating secrets/timestamps. New sessions remain distinct contexts;
changed body shape, method, route or cookie policy refreshes only affected cases.
Historical outcomes survive as stale events. Same-scheme sibling and unrelated
site are separate initiator contexts.

CLI (proposed, offline):

```text
recon csrf plan CAMPAIGN --action ACTION
recon csrf record CAMPAIGN --context CONTEXT --case CASE --event attempted|observed|negative|blocked|inconclusive --bundle BUNDLE
recon csrf status CAMPAIGN [--host HOST] [--action ACTION] --json
```

No network, subprocess, scanner launch or finding promotion.

### 9d. Where the action inventory comes from

1. **Host-role ledger** from actual scoped inventory/imports: application, API,
   admin/dashboard, auth callback, integration/BFF, real-time. Legacy/version
   siblings recorded as separate hosts; discoveries never widen scope.
2. **Declared surface:** forms (action/method/inputs/enctype), JS/fetch clients,
   lazy chunks, sourcemaps, route registries, OpenAPI/Swagger operations and
   alternate spec servers.
3. **Captured surface:** HAR/Burp traffic per test account, role, tenant and
   workflow, including delete/restore, approve/bulk, security settings,
   link/unlink/import, login/logout and real-time actions.
4. **Reconciliation:** UI-only, static/spec-only, capture-only and contradictory
   operations are each explicit states. A declaration is work, not a captured action.
5. **Priority:** ambient-authority identity/security/value transitions first
   (email/password/MFA, linking, roles/permissions, API keys/webhooks, billing),
   then ordinary writes; read-only POSTs are classified rather than assumed.

### 9e. Where, when and how deeply

| Stage | Work |
|---|---|
| L0/L1 | Populate host roles and declared/static actions from scoped inventory |
| L2 | Merge forms, JS routes, chunks, sourcemaps and specs; preserve fieldless/GET operations and method/MIME declarations |
| L4 | Capture legitimate workflows with separate supplied actor browser contexts; reconcile with declared/static |
| Ready-case execution | Baseline → focused server diagnostics (Repeater) → **actual cross-origin browser exercise** → conditional deeper branch → chain handoff |
| Refresh | New session/capture/method/body shape/route/cookie policy reopens affected contexts only |

### 9f. Case families (15)

| Family | Initial hint → technique | Tools |
|---|---|---|
| Baseline / `action-authority` | Captured transition → effective identity, legitimate success, independent state readback, delivery mode; include fieldless writes and GET mutations | Browser, DevTools, Burp |
| Token channels / `token-enforcement` | Form/header/interceptor token → enumerate all accepted channels; complete omission, empty, invalid; duplicate/query-body precedence where relevant | Source review, Repeater, browser |
| Binding/lifecycle / `token-context` | Token design → same-session control, separate sessions/accounts, login/logout/renewal/expiry, URL/cache/Referer leakage; stable per-session tokens can be valid | Two actor contexts, Repeater |
| Double-submit / `cookie-binding` | Cookie/body relationship → naive vs signed/masked; substitution only with an established cookie-planting/shadowing primitive | DevTools, browser, framework docs |
| Origin metadata / `origin-metadata` | Origin/Referer/Fetch-Metadata → exact origins, sibling/cross-site, realistic absent/opaque/referrer-reduced; inspect redirects and missing-header fallback | Browser, DevTools, Burp |
| Cookie/site / `cookie-delivery` | Ambient cookie → navigation vs image/frame/fetch, credentials modes, explicit Lax vs omitted fresh/aged; same-site sibling control required where claimed | Browser/build matrix |
| Representation / `representation` | JSON/API or multipart → URL-encoded/multipart/text-plain accepted shapes, preflight vs actual send, parser strictness; response visibility is not delivery | Browser forms/fetch, DevTools |
| Methods/routes / `middleware-coverage` | Alternate method/version → mutating GET, accepted override params/headers only when browser-deliverable, exact path forms, exempt middleware, legacy versions | Import ledger, Repeater, browser |
| GraphQL / `graphql-operation` | Operation document → selected mutation/side-effecting query, variables shape, persisted/batch identity, GET/POST per operation | Source/capture review, browser |
| Client-side / `client-input-request` | URL/hash/path/message input reaches request builder → trace attacker control with automatic token/credential attachment to owned-state effect | Static tracing, DevTools |
| Login/OAuth / `identity-transaction` | Login/link callback → map start/callback/finish, intended account, session binding, concurrency, reuse/expiry; evaluate state+PKCE+nonce together | Separate browser contexts |
| SAML / `saml-transaction` | SP/IdP flow → session/request correlation, InResponseTo, issuer/recipient/audience, replay, intended association; RelayState allowlisting is not binding | Browser, `hunt-saml` |
| WS/SignalR / `realtime-authority` | Handshake/hub action → cookies vs token, Origin, protected-message authorization; 101 is only transport; negotiate vs WS/SSE/long-poll | Browser, Burp frames |
| BFF / `bff-protection` | Required-header enforcement, exclusions, CORS/preflight, headerless alternatives; backend role/tenant authorization separately | Browser, Repeater, Duende docs |
| Effect chains / `effect-handoff` | Demonstrated action → verification/step-up/link-login/integration consequences; route XSS/OAuth/SAML/authz/SSRF edges to existing workflows | Validator, findings/chain |

Bypass families are conditional on the observed app/browser prerequisites, not
fired indiscriminately. Native header spoofing is diagnostic; the browser must
actually emit the request for a cross-origin claim.

### 9g. Defense-bypass matrix (aggressive testing)

| Defense | Checks |
|---|---|
| CSRF token | Remove/empty/invalid; cross-account/session token; alternate channels; duplicate/precedence; URL/Referer/cache/error leakage; user/action binding |
| Double-submit cookie | Cookie vs body; naive/signed/masked; cookie planting/shadowing only from an established primitive while preserving victim identity |
| SameSite=Lax | Same-site sibling control; top-level GET navigation; redirect POST→GET; `Domain`-scoped overreach; fresh vs aged |
| SameSite=Strict | Sibling-origin control and explicit cookie-domain sharing; same-site alone is not sufficient |
| SameSite=None/omitted | Cross-site form/image/frame/credentialed fetch; measure actual cookie attachment |
| Origin/Referer | Absent/opaque origin, sandboxed iframe, redirect stripping, weak allowlists, scheme/port confusion, trusted sibling; browser-realistic only |
| JSON-only | `text/plain`/urlencoded/multipart, parser differentials, duplicate content-type, charset; check browser emitability/preflight |
| Custom header | Headerless form paths, optional checks; a required static header may be a valid preflight defense |
| Methods | Mutating GET; browser-deliverable overrides; path case/encoding/normalization; legacy endpoints; middleware exceptions |
| GraphQL | GET mutations, operation-level defenses, batching/aliases per operation |
| Client-side | URL/hash/postMessage → request builder with auto credentials/tokens → owned-state effect |
| OAuth/SAML | State/nonce/PKCE/callback binding together; login CSRF; linking confusion between two identities; InResponseTo/replay |
| WS/SignalR | Origin validation, cookie vs token auth, per-message authorization, negotiate/upgrade distinction |
| BFF | Header+CORS/preflight, excluded routes, SignalR carve-out, cookie-domain wildcarding; backend authorization separate |

### 9h. Chains

- CSRF on email/password/MFA change → ATO (`csrf` → `ato`).
- XSS reads token / same-origin fetch → CSRF bypass (`xss` → `csrf`).
- Subdomain takeover or sibling-origin control → same-site CSRF.
- Open redirect → OAuth/SSO callback abuse.
- CSRF on webhook/config → SSRF or integration abuse.
Links use existing `finding link` relations and the chain templates already in
`recon/chain.py`; CSRF actions feed the same realism gate as other completed chains.

### 9i. Tool roles

- **Dedicated browser + DevTools** — real initiation, cookies, preflight, state
  readback; separate attacker/victim profiles.
- **Burp** — capture, history, Repeater diagnostics; generated PoCs are drafts.
- **`recon`** — offline plan/record/status, host/action inventory, reporting;
  no live execution.
- **Optional program-approved scanners** — triage of cookie/header posture only,
  inside the recorded campaign execution plan; no scanner executor is built.
- **Skill handoffs** — `hunt-xss` (token theft), `hunt-oauth`/`hunt-saml`
  (transaction binding), `hunt-ato` (impact chain), `hunt-ssrf` (webhook chains).

External Burp IDs remain external references, never native `fact check` IDs.

### 9j. Build order and tests

| Phase | Files |
|---|---|
| A — contract | `.claude/skills/hunt-csrf/SKILL.md`, `references/{cases,evidence,sources}.md`, notices |
| B — offline core | `recon/csrf.py`; `store.py` helpers; `cli.py` plan/record/status; artifact integrity; zero network |
| C — dispatch/report | `skillmap.py`, `catalog.py`, hunter/validator/reporter prompts, `report.py`, coverage links to `fields.py`/`inputs.py` |
| D — discovery/imports | `har.py`, `burp.py`, `specs.py`, `extract.py`, `active.py`, `score.py`, `pipeline.py`: per-observation MIME/auth, fieldless/GET actions, form enctype, reconciliation |
| E — regressions/docs | `tests/test_recon_csrf.py`, opt-in two-origin browser test, fixtures, skills/imports/report tests, README/Handover |

The owned-loopback two-origin matrix (proposed, not executed) covers: enforced vs
missing token; stable session token; alternate channels; static-header/CORS
correctness; explicit/default-Lax fresh/aged; host-only sibling vs unrelated site;
strict JSON vs simple parser; 200-error vs 204-success with independent state;
exact-origin vs absent fallback; fieldless/GET/middleware variants;
attacker-influenced vs fixed request builder; bound vs swapped OAuth/SAML
transactions; GraphQL operations/transports; WS 101-only vs protected messages;
SignalR transports. Tests assert zero network execution, context non-collision,
stable reimports, selective reopening, redacted metadata, clipped/request-only
Burp records, artifact tampering visibility and preserved finding stages.

Skill evals catch “200 means success,” static-token/header false positives,
a remaining-valid channel masking omission, fieldless/GET omissions, forged-Origin
browser claims and blanket endpoint closure.

### 9k. Implementation status (2026-11-13, branch `recon-engine`, uncommitted)

| Phase | Status |
|---|---|
| A — contract | **Done.** `.claude/skills/hunt-csrf/SKILL.md` + `references/cases.md` (generated from `recon/csrf.py` `CASES`; a test keeps them identical), `references/evidence.md`, `references/sources.md` (pinned commits/hash, licences, corrections). Independently written; no source text copied. |
| B — offline core | **Done.** `recon/csrf.py` (actions/contexts/append-only events, 15 families, 68 variants, facet-scoped staleness, record rules, hash-bound artifacts in `.recon/csrf-evidence/`, `verify`) + `recon/csrfmeta.py` (value-free metadata). CLI `recon csrf sync/plan/record/status/verify`. No `store.py` change was needed. |
| C — dispatch/report | **Done.** `skillmap` `csrf → hunt-csrf`; catalog `hunt_skills` 10 + ledger tool entry; hunter prompt CSRF exception and record command; reporter CSRF line; `coverage.md` CSRF section (per-origin table, next cases, coarse-row conflicts); chain hints `csrf→ssrf`, `subdomain-takeover→csrf`; template `sibling-csrf-ato`. Validator prompt left unchanged. |
| D — discovery/imports | **Done.** `score.py` seeds GET/unknown-method routes with state-change verbs or action selectors and `ws`/`wss`; forms carry enctype + token field names; operations keep per-method MIME/enctype/spec types/auth; HAR/Burp captures keep value-free CSRF metadata; OpenAPI keeps request types, security-scheme authority and form/`formData` fields. |
| E — regressions/docs | **Done.** `tests/test_recon_csrf.py` (31 offline tests) + `tests/test_recon_csrf_browser.py` (two-origin Chromium lab). Suite: **363 tests OK** in `.venv` 3.9.6 (incl. both browser tests) and Homebrew `python3` 3.15.2 (2 Playwright skips); `git diff --check` clean. README, recon/README, Handover, AGENTS updated. |

Browser lab coverage, executed in Chromium 148 (owned loopback; `*.example.com`/`*.example.net`
mapped to 127.0.0.1, all other names forced to fail): Lax withheld on cross-site POST,
sent to a same-site sibling and on cross-site top-level GET (GET mutation); Strict sent to
the sibling, withheld on cross-site GET; omitted SameSite on a fresh cookie **attached** to a
cross-site top-level POST (explicit Lax was not); 200 error envelope with unchanged
readback; token-checked twin unchanged; lenient vs strict text/plain JSON; constant
custom header refused at preflight (POST never sent); simple credentialed fetch
unreadable under CORS yet delivered. All recorded through `CsrfLedger` with the expected
verdicts and rule rejections.

Skill evals (iteration 1, text-only, `.claude/skills/hunt-csrf/evals/`, outputs under
`.recon/skill-evals/hunt-csrf/iteration-1/`): 3 cases × 4 assertions; with skill 12/12,
without skill 12/12. Non-discriminating: the baseline learned the workflow from the
updated AGENTS.md, hunter prompt, recon/README and CLI help, so these measure repo
integration rather than the skill alone. The with-skill run surfaced two engine gaps,
both fixed with regression tests: captured GraphQL traffic never attached to
per-mutation actions (imports now record operation type+name, never documents or
variables), and camelCase names (`updateEmail`, `/api/deleteItem`) missed priority
and verb matching.

Matrix rows **not yet in the browser lab** (covered offline by rule tests, or open):
alternate token channels and stable per-session tokens in a browser; exact-origin vs
absent-Origin fallback; aged default-Lax (needs a >2-minute wait); fieldless/middleware
path variants; client-side request builder; OAuth/SAML transaction stubs; GraphQL
transports; WebSocket 101-only vs protected messages and SignalR transports; clipped /
request-only Burp records. Live use still needs a configured campaign and the connected
dedicated browser.

## 10. SSTI hunting program (next hunt build, 2026-11-13)

SSTI becomes an **input × render-surface hunt with a proof ladder**. The unit of coverage
is one input (endpoint, method, location, field, account/role/tenant/workflow) as rendered
on one surface: the submission response, a later page, another role's view, an email, a
PDF/export, or an async job. Evaluation is proven by **marker-bracketed output in the raw
HTTP response or a delivered artifact**; impact by the highest proven rung of the ladder.
The engine mints probes, classifies stored captures and artifacts, fingerprints engines
and keeps the ladder offline. Probes are submitted in the dedicated browser through Burp
(or under the campaign execution plan) and the captures imported. Today `ssti` rows route
to `hunt-sqli`, which says nothing about templates; this build gives them their own skill.

### 10a. Source selections

| Source | Snapshot | Take | Do not import |
|---|---|---|---|
| HackTricks fork `b4rdia/HackTricks`, `pentesting-web/ssti-server-side-template-injection/` (README, jinja2-ssti, el-expression-language) | branch `9d61d9142c350c1f6188ffb3c5e6e34407cf8438`; folder last touched `1d1f2554c96d0ae01edfa5d45d6af25199669f97` (2023-01-13); CC BY-NC 4.0 | ideas: detect → identify → exploit; plaintext vs code context and expression break-out; transform probes between random markers; error-based identification; read-only exploration of documented default objects; the **sandbox model** (engines that are code, engines with a documented sandbox, logic-less engines) with version hardening; the **filter taxonomy** (alternate delimiters/expression kinds, attribute access without dots/underscores/brackets/quotes, string building from parts and character codes, encoding layers, strings smuggled through other parameters/headers) | all prose, tables, payloads, gadget chains, subclass-index hunting, images; the 2015 decision-tree image (wrong leaves); tplmap as a primary tool |
| mind-hunt `skills/hunt-ssti/SKILL.md` (local, 51 lines) | SHA-256 `30e314db34f5324c2ee0f2d9a20d02f0bd9b0076e8c46a348125be539b392766`; MIT, © 2026 MindflareX | the **ladder** (detect → fingerprint → escalate), the surface list (email templates, PDF/report generators, CMS previews, error pages, reflected headers), the **chains** (→ execution, → XSS when sandboxed, → SSRF through fetch features, file upload → SSTI through re-rendered documents), the **Pre-Severity Gate** (sandboxed evaluation is a medium template injection, not critical RCE; prove execution with a unique marker or OOB callback first) | its RCE payloads and payload tree; the false fingerprints (`#{7*7}`→Mako, `${7*7}`→Velocity, `*{7*7}`→Spring Thymeleaf, `7*'7'` as Jinja2-only); payout figures; references to `hunt-rce`, `hunt-file-upload`, `security-arsenal`, `triage-validation` (not BugVault skills) |
| BugBountySkills `KNOWLEDGE_BASE/SSTI/` (10 files) | commit `0accf5fdc71ec7f03273aebb99268a8609f8dfd4`; MIT, © 2026 0xN0RMXL | report leads only, re-checked against HackerOne: #1104349 (sign-up name evaluated in the welcome-email subject, engine unknown, later emails stopped after probing), #423541 (merchant-editable notification templates; Handlebars per the reporter's write-up); triage leads #1265344 (AngularJS client-side, closed as self-DoS), #904672 (app compiling user strings in its own test page, informative), #942103 (development-only ERB test server, severity none) | the templated payload/bypass/cheatsheet files, the misattributed Rails excerpt, every statistic and bounty figure |
| Primary engine documentation (27 engines; `engine_fingerprints.md`) | official docs, tagged doc/source/inferred | the engine table in code: delimiters, arithmetic, string×integer behaviour, comment syntax, built-ins, error signatures, sandbox modes | — |

### 10b. Corrections carried into the engine and skill

- `{{7*7}}`→49 is shared by Jinja2, Twig, Nunjucks, Pebble, Jinjava, Tornado and Blade; it
  identifies a family, never an engine. `7*'7'` splits Python (repeat) from PHP/JS/EL
  (numeric) and errors in FreeMarker, Ruby, Groovy and SpEL; Tornado also repeats.
- `#{}` is not Mako; Velocity prints `${7*7}` literally; `*{}` is evaluated only in Thymeleaf
  `th:*`/inlining and means OGNL-or-SpEL Thymeleaf, not "Spring".
- Django, Liquid, Handlebars, Mustache and Go have no `*`: logic-less engines are detected
  with section pairs, comment elision and their own filters (`times`, `add`, `printf`).
- An error page is not proof: SQL, JSON and WAF layers error too. An error counts only when
  it carries an engine signature that the literal control does not trigger.
- Sandbox claims are version-bound (Jinja2 2.8.1/2.10.1/3.1.5/3.1.6, Twig 3.0.5+,
  FreeMarker 2.3.30, Thymeleaf 3.0.12/3.0.14, Handlebars 4.6.0, Pebble 2.5.0/3.1.4,
  Smarty 4/5, Jinjava 2018); identification records the version evidence.
- Evaluation only in the browser is client-side template injection (`hunt-xss`). An app
  compiling user strings in its own test page, or a development-only server, is a triage
  question, not a production finding.
- Detection tools prove evaluation and a best-guess engine, not exploitability under the
  target's version, sandbox and program rules.

### 10c. Where and when

`recon/score.py` seeds `ssti` rows in tiers (reason text names the tier):

1. template-ish fields (`template`, `tpl`, `layout`, `theme`, `view`, `format`, ...);
2. inputs on render/export/preview/notification/email/invoice/report paths, content
   fields (name, subject, title, message, bio, address) that servers re-render in mail,
   PDFs and admin views, and upload/import surfaces (uploaded templates and documents);
3. every other parameterized input (low prior: one polyglot submission per field).

Surfaces to walk per input: the submission response; later views of the stored value
(profile, list, search, admin/support consoles, other roles); outbound email subject and
body (welcome, invite, reset, notification, digest); PDF/invoice/report/export renders;
preview and "send test" features; template/theme editors; error and 404 pages echoing
the path; reflected headers in log viewers (User-Agent, Referer); view names taken from
the path; uploaded DOCX/ODT/XLSX mail-merge, SVG/HTML/Markdown renders and file names.

When: after L4 capture (the field and its workflow exist in the field ledger), one probe
set per field. Stored fields are probed once on a supplied test account, then every
later capture and delivered artifact is traced.

### 10d. The ladder (case families; per input × surface)

| Case | Rung | Gate | Machine evidence for `observed` |
|---|---|---|---|
| `detect` | detect | standard | an evaluated probe (product, sum, printf, repeat, upper, section pair) between its markers, or a blind error differential |
| `confirm` | confirm | standard | ≥2 evaluated probes with different operands, the literal control not evaluated, evidence outside a DOM-only artifact |
| `context` | context | standard | operator: plaintext / expression / string-literal / statement |
| `identify` | identify | standard | the named engine is the only consistent candidate, or its error signature is on this surface |
| `sandbox` | sandbox | standard | operator: none / sandboxed / hardened / logic-less, from the sandbox model |
| `impact-read` | read | `context-names` standard; `config-read` grant `context`; `file-read` grant `file-read` | distinct evidence/control artifacts |
| `impact-exec` | execution | grant `execution` | the set's execution marker in the evidence and absent from the control; OOB host approved |
| `blind` | detect | `error-differential`/`boolean-error` standard; `side-channel` grant `execution` | pair responses: the runtime-error twin differs, the valid twin and control do not |
| `stored` | detect | standard | evaluation on a surface other than the submission response |
| `filter-bypass` | detect | standard | map elements with `recon waf plan --set ssti`, then a bypass family per blocked element |
| `chain-xss` | chain | standard | unescaped template output in a browser surface, or the CSTI split |
| `chain-ssrf` | chain | standard (approved receiver); internal reach via `hunt-ssrf` grants | — (hand-off) |
| `chain-upload` | chain | standard | evaluation of probes carried inside an uploaded file |
| `severity-gate` | report | standard | the claimed severity does not exceed the ceiling of the highest proven rung |

Grants live in `scope.json` as `ssti.depth_grants` (`context`, `file-read`, `execution` or
`"all"`), copied from the program's written rules, like `ssrf.depth_grants`.
`ssti.per_case_effort_cap` (default 3) is per case and context. Callback receivers come from
`ssti.callback_hosts` (fallback `ssrf.callback_hosts`).

### 10e. Probe design

- Every probe sits between two unique `[a-z0-9]` markers derived from the set's seed, so
  plain, URL-encoded and HTML-escaped forms coincide and every output is attributable.
- Operands are derived per probe, giving distinct 6–7 digit products; matching tolerates
  locale grouping (`1,234,567`, `1.234.567`, NBSP) and a trailing `.0`.
- Stages: (1) three **polyglots** (common: `{{}}` `${}` `#{}` `<%= %>`; rest: `{}` `@()`
  `[[${}]]` `%{}` `#set`; logic-less: Liquid `times`, Django `add`, Go `printf`, Mustache
  section pair) plus the literal **control**; (2) the **family split** (one probe per
  family), the parser-**error probe** (synchronous surfaces only), the bare expression and
  break-out probes for **code context**; (3) **identification**: comment elision per
  syntax, string×integer per family, built-ins (`|upper`, `?upper_case`, `.upper()`,
  `.toUpperCase()`, `.upcase`, `|upcase`, `.ToUpper()`, `#strings`), `#{2^3}`, `{l}{r}`;
  (4) **blind** pairs.
- `--compact` emits short markers and operands for length-limited fields; every probe is
  printed raw, URL-encoded and JSON-escaped.
- The fingerprint is computed from the doc-verified engine table, not a static tree: every
  observation eliminates inconsistent engines, and the next suggested probe is the one
  that splits the remaining candidates most evenly.

### 10f. Blind SSTI

- **Error differential**: per family, a valid twin and a runtime-error twin that differ by
  one character (division by one vs zero; a call on a non-function for JS engines), plus
  the literal control. Evaluation is proven when the error twin's response differs (5xx,
  different template) while the valid twin and the control match.
- **Boolean error**: the conditional twin raises only when the condition is true.
- **Side channel** (time, OOB): needs an execution-capable expression, so it runs only under
  the `execution` grant, with the approved receiver and the set's marker, bounded delays
  (≤10 s, repeated with a control).
- Email/PDF surfaces that cannot be observed stay `inconclusive`, never negative.

### 10g. Stored and second-order SSTI

- One probe set per stored field, submitted once on a supplied test account. `recon ssti
  trace` searches every capture after the set was minted, plus artifacts: `.eml` (subject
  and decoded parts), PDF (raw and inflated streams), saved DOM, exports.
- Delayed rendering: the set stays open; traces can be re-run as later captures and
  emails arrive. Async jobs are declared surfaces until their output is captured.
- Side-effect caution (#1104349): probes can break mail and render pipelines. Use the
  smallest stage on stored fields, confirm later notifications still arrive, and restore
  the field afterwards (`stored`/`restore`).

### 10h. Filter bypass

- Map first: `recon waf plan --host H --set ssti` emits template elements (delimiters,
  structural characters, commonly filtered identifiers); outcomes are recorded with
  `recon waf record --kind template|char|identifier`.
- The bypass families (categories, no payload lists), chosen per blocked element:
  delimiter alternative, character avoidance, string building, encoding layer, parameter
  smuggling, context break-out. `ssti plan` lists the blocked elements and the families
  that apply; each attempt is one `filter-bypass` variant.

### 10i. Identification and the sandbox model

- Classes: **template is code** (Mako, Tornado, ERB, EJS, Pug, Slim, Razor, Blade,
  Groovy, Nunjucks, non-sandboxed Jinja2, FreeMarker without a mode); **documented sandbox
  or restricted mode** (Jinja2 SandboxedEnvironment, Twig Sandbox, Smarty security, Latte
  sandbox, Velocity SecureUberspector, SpEL SimpleEvaluationContext, Thymeleaf restricted
  mode, Pebble method validator); **logic-less by design** (Mustache, Handlebars without
  unsafe helpers, Liquid, Go with trusted authors).
- The engine table carries the documented sandbox and the version hardening notes; the
  `sandbox` case records which applies, with version evidence where documented
  (`${.version}`, `{$smarty.version}`, Twig's version constant).

### 10j. Chains

| From | To | Link | Notes |
|---|---|---|---|
| file upload (template editors, mail-merge documents, SVG/HTML/Markdown renders, file names) | SSTI | `enables` | probes inside the uploaded file; the rendered output is traced |
| SSTI (sandboxed or logic-less) | stored XSS | `spawns` | template output unescaped in a browser surface; hand-off to `hunt-xss` |
| SSTI evaluated only client-side | CSTI/XSS | — | not SSTI; `hunt-xss` |
| SSTI with a fetch feature (include/import from URL, renderer fetches, custom helpers) | SSRF | `pivots-to` | approved receiver first; internal reach under `hunt-ssrf` depth grants |
| SSTI | information disclosure | `yields-token` | context/config read under the `context` grant, redacted |
| SSTI | execution → scope-capped action | `escalates-via` | `execution` grant; one marker-bearing benign proof; `ssti-exec` chain |

New chain templates: `upload-ssti-exec`, `ssti-fetch-ssrf`, `ssti-stored-xss`; new hints
`file-upload→ssti`, `ssti→xss`, `ssti→ssrf`.

### 10k. Pre-severity gate

Severity ceiling per input × surface from the highest proven rung: evaluation → medium
(low for a logic-less engine without data access); read (config or file) → high;
execution → critical. `recon ssti record --case severity-gate --severity X` is refused
above the ceiling. Evaluation is not code execution; a sandboxed engine stays medium until
an escape is proven.

### 10l. Architecture (`recon/ssti.py`, offline)

- Tables `ssti_sets` (input context, seed, compact flag, capture watermark),
  `ssti_surfaces`, `ssti_observations` (machine classifications, idempotent),
  `ssti_case_events` (append-only operator events with hash-bound artifacts in
  `.recon/ssti-evidence/`).
- `ENGINES` (27 engines; expectations tagged doc/source/inferred) generates
  `references/engines.md`; `CASES` generates `references/cases.md`; tests keep them equal.
- CLI `recon ssti probes|trace|fingerprint|plan|record|status|verify`.
- Classifier outcomes: evaluated (and repeat/numeric/upper/elided/escape/pow/xor/braces
  transforms), literal (raw or escaped), empty, altered, truncated, error (engine
  signature or 5xx without markers), blocked, absent, coincidence, client-evaluated (DOM
  only while HTTP shows the literal).
- Field-ledger coupling: machine evaluation marks `ssti-eval` observed for the field; a
  recorded detect negative marks it negative when no surface evaluated. `identify` writes
  a `template` fingerprint, and `recon fields packet` for `ssti-*` cases requires it
  instead of the DB/CSP fingerprints.
- `coverage.md` gets an SSTI section (per host, next cases, candidate inputs without a
  probe set, coarse rows contradicted by open cases). Hunter prompt, skill map, catalog,
  input census and chains are wired; the validator prompt stays unchanged.

### 10m. Tools

`recon ssti` (offline), Burp (Repeater as diagnostics, history export for the trace),
`recon waf`, Burp Collaborator or an approved receiver (only under `execution` for OOB).
Operator-run detection tools under the standing execution plan: TInjA (detection and
identification, SSTI and CSTI, no blind) and SSTImap in detection modes (its shell/file
modes exceed most program rules); tplmap is legacy (unmaintained since 2018). Tool output
is a lead until traced.

### 10n. Build order and verification

| Phase | Files |
|---|---|
| A — contract | `.claude/skills/hunt-ssti/SKILL.md`, `references/{cases,engines,bypass,evidence,sources}.md`, evals |
| B — offline core | `recon/ssti.py`; CLI; artifacts; zero network |
| C — dispatch/report | `skillmap` `ssti → hunt-ssti`; catalog (11 hunt skills, tool entries); hunter prompt; `coverage.md` section; chains/hints; `waf.py` `--set ssti`; `fields.py` template fingerprint; `inputs.py` |
| D — discovery | `score.py` tiered seeding and upload surfaces |
| E — regressions/docs | `tests/test_recon_ssti.py` (offline rules) + an owned-loopback lab with emulated Jinja-like and FreeMarker-like engines (ast-whitelisted, no `eval`), reflected-only and escaped negatives, a stored email surface, a blind error-only endpoint and a CSTI-only page; README, recon/README, Handover, AGENTS |

A real-engine lab (Jinja2 in `.venv`) is optional and needs approval to install the
package.
