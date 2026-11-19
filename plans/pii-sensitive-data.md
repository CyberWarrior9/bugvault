# Build plan — `hunt-pii-leak`

PII and sensitive-data exposure for BugVault.
Drafted 2026-11-16. Target branch `recon-engine`. Baseline: 511 tests green.

---

## 1. Status — primitives exist, and `info-disclosure` is now taken

The JS-bundle work landed since the last review. `recon/jsintel.py` seeds
`info-disclosure` at `:166` and `:205`, `recon/jspackets.py:21` already sets a
severity ceiling for it —

> `info-disclosure` only if source is non-public and lower-role delivery is
> policy-relevant

— and `skillmap.py:32` routes `"info-disclosure": ("hunt-js-bundle",)`.

So **`info-disclosure` is the served-file class now**: secrets, source, config
exposed in artifacts the server hands out. PII is a different shape and needs its own
class (§8).

Existing primitives this skill builds on:

| Primitive | Anchor |
|---|---|
| `AUTH_HEADERS` — authorization, cookie, x-api-key, x-auth-token, x-access-token, x-csrf-token, x-xsrf-token, api-key, token, x-session-token | `har.py:33-34` |
| `SENSITIVE_PARAM` — `token\|secret\|password\|passwd\|cookie\|auth\|session\|csrf\|xsrf\|otp\|pin\|key` | `har.py:30` |
| `SECRET_PATTERNS` — AWS key id, Google API key, Slack token, Stripe live secret, and more | `extract.py:~122` |
| `redact()` → `first6…(len N)` | `extract.py:176` |
| **Canary propagation map** — mint a marker, trace where it surfaces across all stored traffic | `fields.py` `canary()` / `trace()` |
| HAR import with account / role / tenant / workflow labels | `captured-auth-mapping` |
| `info-disclosure → access-control` ("leaked key/token/ID → authenticated access") | `findings.py:108` |

**What's missing:** every one of those is *input*-side or *secret*-shaped. There is no
output-side person-data vocabulary, no response-versus-page diff, no collection-size
reasoning, and no `pii-exposure` class.

---

## 2. Organizing thesis — your own record is the probe

> A PII finding is not "I saw personal data." It is **"a field crossed a boundary it
> should not cross"** — and you can prove that with a record you own.

Two consequences, and they shape the whole plan:

**1. The canary is already built.** `fields.py` `canary()` mints a unique marker;
`trace()` scans every stored request and body for it in raw and base64 form, bounded
by `MAX_TRACE_SCANS = 5000` / `MAX_TRACE_BYTES = 100MB`. Put a marker in *your own*
profile field, then see where it surfaces: another account's response, an admin view,
an email, a PDF or CSV export, a search index, a log endpoint. **Each surface is a
boundary crossing, demonstrated with your own data.**

**2. Volume adds nothing to the finding.** One record establishes the control is
absent. A thousand establishes the same thing while making the report unusable — and
ARTEX Phase 10 names the right artifact instead: *"persist every confirmed finding as
a replayable request (curl command or HAR artifact) so retests and the reporter can
re-verify,"* plus *"mark which findings are safe to re-run and which are one-shot."*
The replayable request is the proof; the records are not.

So the hunt is: **find the boundary, cross it with your own data, record the request
that crosses it.**

---

## 3. Source map

### mind-hunt — `hunt-pii-leak/SKILL.md`, 112 lines

SHA-256 `5bd17cb74178dad21158b4950b9c63643d9f5dbcf23fb7d6f15617bbc1e8c49d`

Its framing: *"the GOLDEN GOOSE per `archangel` ($40-50K LHE workflow). Almost every
program treats mass PII leak as Critical full-stop."*

| Take | Anchor |
|---|---|
| **"What counts as mass PII"** — the definitional section, and the one thing no other source attempts | L10-22 |
| **Seven surfaces, ranked** (§4) | L23-62 |
| Real disclosed examples | L63-74 |
| Test recipe | L75-92 |
| **Pitfalls** | L93-99 |
| Chain-up | L100-106 |

Its surface #3 says to find debug and staff routes *via `hunt-jsbundle`* — the same
dependency the cloud plan has, and `hunt-js-bundle` now exists.

### ARTEX — `skills/api-security/SKILL.md` Phase 9, and Phase 10

**Phase 9: data exposure** — five checks, and the first is the best technique in the
whole source set:

```
- response fields beyond what the UI renders (diff the API response against the page)
- pagination enumeration: ?page=1&limit=10000
- error messages leaking stack traces, internal paths, or SQL
- GraphQL nested traversal reaching unauthorized data
- spec files exposing internal endpoints
```

**Phase 10: regression handoff** — the replayable-request artifact and the
safe-to-re-run versus one-shot distinction (§2).

Plus the doctrine at `agent/promptcatalog.go:42-82`: measured impact with a
denominator, proof basis, and distinct entry points as distinct findings.

ARTEX also ships `notify/redact.go` with tests — its own PII redaction for
notifications. Worth reading as a redaction-pattern reference when writing reports,
not as hunting method.

### PentAGI — essentially nothing, again

Five `PII` hits, led by `backend/pkg/server/services/anonymizer.go` — its own
telemetry anonymiser. `sensitive data` (18) and `personal data` (2) are its EULA,
installer docs and `examples/prompts/scope_of_work_pentest.md`. No hunting method.
Eighth category with no contribution.

### BugBountySkills — both relevant folders are shells. Eight for eight.

These two looked the most promising in the whole repo: real `CWE-200`, and the
highest average bounties in its metadata (`$2,257` and `$1,877`). Reading them:

| Folder | theory | methodology | bypasses | payloads | domain markers |
|---|---|---|---|---|---|
| `Information_Disclosure/` | 163 | 86 | 117 | 180 | **4 across 546 lines** |
| `Sensitive_Data_Exposure/` | 74 | 89 | 119 | 207 | **4 across 489 lines** |

Markers searched: PII, redact, mask, personal, SSN, email, phone, GDPR, tokeniz,
field-level, export. Four hits per folder across ~500 lines each, with
`hunting-methodology.md` and `bypasses.md` scoring **zero in both**.

**Eight folders from this repo have now been read directly and all eight were
generated shells** — including the two with genuine CWEs and the best headline
numbers. The metadata is not a quality signal at any value. Report-ID indexes only;
this is settled and worth not re-testing.

### HackTricks — no dedicated page

`pentesting-web/` has no PII or sensitive-data-exposure page. The adjacent material
is scattered: `parameter-pollution.md`, the GraphQL content, and the error-disclosure
notes inside other pages. Use it for the GraphQL traversal technique only.

### PortSwigger Web Security Academy — Information disclosure

`https://portswigger.net/web-security/information-disclosure` plus its labs. The
correctness baseline, and the one source that systematically covers the *channels*
data leaks through — error messages, debug pages, backup files, source maps,
`robots.txt`, version-control directories, `TRACE`, and insecure configuration.

### OWASP WSTG — the test-procedure source

`4-Web_Application_Security_Testing/` carries structured tests for sensitive data in
transit and at rest, error-handling disclosure, and credentials over unencrypted
channels. Primary-ish, and it gives procedure where blogs give anecdote.

---

## 4. Which endpoints — the surface inventory

mind-hunt's seven, with BugVault's existing signal for each:

| # | Surface | What leaks | BugVault signal |
|---|---|---|---|
| 1 | **GraphQL bulk fetch** (`users(first:N)`) | whole collections | ✅ `graphql_ops` from `extract.py`, `burp.py` |
| 2 | **Search endpoints** | email, phone, internal IDs via index fields | ⚠️ `SEARCHISH` exists in `fields.py` for triggers |
| 3 | **Debug / staff routes** | unfiltered records | ✅ now via `hunt-js-bundle` route extraction |
| 4 | **Mobile API endpoints** | `access_token` and PII the web API strips | ⚠️ `apk-static-mapping` exists; not linked |
| 5 | **Address book / contacts / friends** | other users' identities, often unauthenticated | ❌ |
| 6 | **Export / report endpoints** | everything, bypassing field-level ACLs | ✅ `EXPORTISH` in `fields.py` |
| 7 | **Old / staging hostnames** | production data with debug on | ⚠️ version-sibling assets exist |

Add four the sources imply but mind-hunt doesn't list:

| Surface | What leaks |
|---|---|
| **Collection endpoints with pagination** | the cap is a control, not a boundary (ARTEX Phase 9) |
| **Expansion parameters** (`include=`, `expand=`, `$expand=`, `fields=`) | joined records the entry point guards — same root cause as the OData `$expand` IDOR |
| **Error and stack-trace surfaces** | internal paths, SQL, record fragments (ARTEX Phase 9, PortSwigger) |
| **Notification and webhook payloads** | records delivered to an endpoint you control |

### Which parameters

Two vocabularies are needed and only the input side exists today.

**Output-side person fields** — the new vocabulary, matched on response bodies and
spec schemas:

```
identity     email, phone, mobile, name, first_name, last_name, full_name, username,
             display_name, dob, date_of_birth, gender, nationality
government   ssn, national_id, tax_id, passport, license, nin, aadhaar
location     address, street, city, postcode, zip, lat, lng, geo, ip_address
financial    card, pan, last4, iban, account_number, routing, balance, salary
health       diagnosis, medication, insurance, policy_number
internal     internal_id, user_uuid, tenant_id, employee_id, created_by, owner_id
auth-adjacent access_token, refresh_token, session_id, reset_token, otp, api_key
```

The last row overlaps `info-disclosure`; §8 resolves which class claims it.

**Control-side parameters** — the knobs that widen a response:

```
pagination   limit, per_page, page_size, count, first, last, offset, cursor, after, before
expansion    include, expand, with, embed, populate, fields, select, $expand, $select
scope        all, scope, visibility, status, role, tenant, org, team
format       format, export, type, download, output
sort         sort, order_by, orderby, direction        # leaks protected columns
```

---

## 5. The blockers, and how each is defeated

This is the heart of the skill. Every row is a control that hides data, and defeating
it **is** the finding — the control's absence on an alternate path is the
vulnerability, not a workaround.

| Blocker | What it does | How it falls |
|---|---|---|
| **UI masking** | page shows `***-**-1234`; the API returns the full value | **Diff the API response against the rendered page** (ARTEX Phase 9 #1). The single highest-yield check in the class, and it needs one request |
| **Field-level redaction** | some fields stripped per role on the primary path | Take an alternate representation: the export path, the GraphQL field, the mobile API, an older API version, an `include=` expansion, the `sort`/`order_by` channel |
| **Pagination cap** | `limit` silently clamped | Raise it (`limit=10000`), walk the cursor, offset past bounds, or switch to the GraphQL `first:`/`after:` form. **A cap is a control; proving it is unenforced is the finding — not a reason to harvest** |
| **Tokenization** | real value replaced by a surrogate | Find the detokenisation endpoint, or an endpoint returning pre-tokenisation data — reconciliation, admin, and webhook payloads are the usual three |
| **Authz on the primary path only** | the sibling path lacks the check | Export, print, report, search-index and bulk paths. Same case as `ac-surface` in the access-control plan — chain to it rather than duplicating |
| **Rate limit on enumeration** | slows the collection walk | The batch or bulk variant, GraphQL aliasing, or a different endpoint returning the same records. Note: if you need volume you have misread the finding |
| **Search-index scoping** | index holds more than the UI queries | Query it directly, field-targeted and wildcard queries, and read what the index returns versus what the UI shows |
| **Debug suppression in production** | stack traces off | Old and staging hostnames (mind-hunt surface 7), version siblings, and error paths the main host still exposes |
| **GraphQL depth or complexity limits** | blocks nested traversal | Fragments, aliasing, persisted-query forms, and splitting one deep query into several shallow ones |
| **Response-size caps** | truncates | Field selection to fit under the cap, or the export path that has no cap |

Two cross-cutting points worth recording as technique:

- **The masked field and the unmasked field are often the same request.** Before
  reaching for a bypass, read the full raw response — masking is frequently applied
  only by the renderer.
- **The control that blocks you tells you which path is guarded.** A clamped `limit`
  on the primary endpoint and an unclamped one on `/export` is the finding, stated
  precisely.

---

## 6. Case ladder

| Case | Established |
|---|---|
| `pii-surface` | an endpoint returning person-shaped fields is identified, with its collection shape (single / collection / export) |
| `pii-fields` | the response's person-field set enumerated and diffed against what the UI renders |
| `pii-mask-gap` | a field the UI masks is returned unmasked on some path |
| `pii-boundary` | **your own canary field surfaces where it should not** — another account, a lower role, an admin view, an email, an export, an index |
| `pii-unauth` | person data returned with no credential |
| `pii-cross-role` | person data returned to a role that should not see it |
| `pii-cross-tenant` | person data returned across a tenant boundary |
| `pii-scale` | the collection control is unenforced — demonstrated by the *cap being absent*, with a count, not by retrieving the collection |
| `pii-channel` | data leaks through a secondary channel: error, log endpoint, notification, webhook, search index |

`pii-boundary` is the case the canary machinery already supports and the one that
proves a leak without touching anyone else's record.

`pii-scale` is deliberately phrased as the control's absence. ARTEX's "measured
impact with a denominator" fits exactly: *"the documented cap is 100; the endpoint
returned 2,500 records in one response"* — the number is the denominator, not a
dataset.

---

## 7. Chaining

```
inbound
  js-extract        -> pii-exposure     debug/staff routes, mobile API hosts (hunt-js-bundle)
  apk-static        -> pii-exposure     mobile endpoints the web API does not expose
  access-control    -> pii-exposure     an unguarded sibling path returns records
  idor-bola         -> pii-exposure     object substitution reaches another person's record
  cloud-misconfig   -> pii-exposure     readable storage holding exports or backups

outbound
  pii-exposure      -> ato              leaked reset token, OTP or session reference
  pii-exposure      -> info-disclosure  the same response also carries a key or config
  pii-exposure      -> access-control    leaked internal IDs enable a guarded action
```

`chain.py:73` and `:88` already route `info-disclosure` into reset-token and
render-exposure chains — the `pii-exposure → ato` row mirrors that for person data.

---

## 8. Class design — a new class, not a second skill on `info-disclosure`

`info-disclosure` is now seeded by `jsintel.py` and routed to `hunt-js-bundle`, with
a ceiling rule at `jspackets.py:21`. Overloading it would collide.

| Class | What leaked | Owner |
|---|---|---|
| `info-disclosure` | secrets, source, config, internal paths — in served artifacts | `hunt-js-bundle` |
| **`pii-exposure`** (new) | person records reaching a party that should not receive them | `hunt-pii-leak` |

The boundary rule, for the overlapping `auth-adjacent` field row in §4: **the class is
decided by what leaked.** A credential or config value → `info-disclosure`. A person
record → `pii-exposure`. A response carrying both seeds both, and they chain.

Seeding rule — output-shaped, which is new for `score.py`:

```python
# person-field vocabulary matched against observed response bodies or spec schemas,
# not against request parameter names
if person_fields_in_response:
    out["pii-exposure"] = f"person-shaped response fields: {fields[:6]}"
    if collection_shape:
        out["pii-exposure"] += f"; collection endpoint, cap {observed_cap or 'unknown'}"
```

Then `"pii-exposure": ("hunt-pii-leak",)` in `skillmap.py`.

This is the first seeding rule keyed on **responses** rather than requests, so it
needs the stored-response path rather than the asset attrs — `score.py` currently
reads `params`, `methods` and `attrs`.

---

## 9. Implementation shape

### `recon/pii.py` — vocabulary and classification

```python
PERSON_FIELDS      # the six §4 categories, leaf-normalised like CONTENTISH
CONTROL_PARAMS     # pagination | expansion | scope | format | sort
GOV_ID_SHAPES      # structural validators, not value stores: length/checksum shape
                   #  only, so a field can be classified without retaining the value

classify_response(body, content_type) -> {
    "person_fields": [...], "collection": bool, "record_count": int,
    "sensitivity": "identity|government|location|financial|health|internal"
}
mask_state(value) -> "masked|partial|full"      # ***-**-1234 vs full
```

`GOV_ID_SHAPES` matches *shape*, never retaining the value — the same discipline
`redact()` already applies to secrets.

### `recon/pii.py` — the ledger

```
pii_surfaces
  id, asset_id, origin, route, method, collection_shape,
  person_fields, sensitivity, documented_cap, observed_cap,
  discovery_basis, priority, created, updated
  UNIQUE(asset_id, method, route)

pii_case_events
  id, surface_id, case_id, state, attempt_kind,
  account, role, tenant,                      -- whose view produced this
  marker,                                      -- the canary, for pii-boundary
  field_name, mask_state_ui, mask_state_api,  -- the diff, for pii-mask-gap
  record_count, cap_claimed,                   -- the denominator, for pii-scale
  response_ref, control_response_ref,
  replay_artifact,                             -- ARTEX Phase 10
  one_shot,                                    -- safe to re-run?
  note, created
```

`field_name` plus the two `mask_state` columns make `pii-mask-gap` a single-row fact:
this field, masked in the page, full in the API.

`record_count` and `cap_claimed` give `pii-scale` its denominator without storing
records.

`replay_artifact` and `one_shot` implement ARTEX Phase 10 directly.

**No response bodies are stored in this ledger** — `response_ref` points at the
existing response store, and the ledger holds field names, mask states and counts.
That is what makes the evidence re-readable weeks later without the ledger itself
becoming a PII store.

### CLI

```
recon pii surface <campaign>              person-field surfaces with collection shape
recon pii diff    <campaign> --surface N  API response vs rendered page field diff
recon pii canary  <campaign> --surface N  mint a marker for the boundary test
recon pii trace   <campaign> --marker M   where the marker surfaced  (wraps fields.trace)
recon pii plan    <campaign> [--surface N]  ranked surface x case cards
recon pii record  <campaign> --surface N --case C --state S ...
recon pii status  <campaign>              coverage and the blocker map per surface
```

`recon pii trace` wrapping the existing `fields.trace()` is the whole `pii-boundary`
implementation — the machinery is built, it just has no PII-shaped entry point.

---

## 10. Proof binding

`factcheck.py` accepts `status_is`, `header_present`, `header_equals`,
`body_contains_raw`.

| Case | Binding |
|---|---|
| `pii-mask-gap` | `body_contains_raw` on the **unmasked** form in the API response, with the page response as `control_response_ref` showing the masked form |
| `pii-boundary` | `body_contains_raw` on your own canary marker in the response that should not contain it |
| `pii-unauth` | `status_is` plus `body_contains_raw` on a person field, with an authenticated control |
| `pii-cross-role` / `pii-cross-tenant` | the same request under two principals, both responses stored |
| `pii-scale` | `record_count` against `cap_claimed`, with the documented cap cited |
| `pii-channel` | `body_contains_raw` on the marker in the secondary channel's payload |

Every one of these is satisfiable with **your own canary marker or your own two test
accounts**. None requires reading a third party's record — which is also why they
survive triage: the request is replayable by the triager against their own data.

---

## 11. Wiring

```
.claude/skills/hunt-pii-leak/SKILL.md
.claude/skills/hunt-pii-leak/references/{surfaces.md,blockers.md,vocabulary.md,sources.md}
.claude/skills/hunt-pii-leak/evals/{canary-not-corpus,mask-diff-recorded,cap-is-the-claim,class-boundary}/
recon/pii.py                vocabulary, classification, ledger
recon/score.py              pii-exposure seeding on response shape (§8)
recon/catalog.py            HUNT_SKILLS entry
recon/skillmap.py           "pii-exposure": ("hunt-pii-leak",)
recon/findings.py           five inbound + three outbound chain rows (§7)
recon/cli.py                pii verb group
tests/test_recon_pii.py
tests/test_recon_pii_vocab.py       classification and mask_state fixtures
AGENTS.md                   pii-exposure bullet
Handover.md                 pii.py row
```

Gate: discover over `tests`, green at 511+.

---

## 12. Evals

**`canary-not-corpus`** — a `pii-boundary` or `pii-cross-tenant` event whose evidence
is a third party's record rather than a minted marker or an owned test account must
fail. The canary machinery exists; using it is both the correct proof and the faster
one.

**`mask-diff-recorded`** — a `pii-mask-gap` recorded without both `mask_state_ui` and
`mask_state_api`, and without a `control_response_ref`, must fail. "The API returns
the SSN" is only a finding against the page that masks it.

**`cap-is-the-claim`** — a `pii-scale` event recorded without `cap_claimed` and
`record_count` must fail. The denominator is the finding; a retrieved collection is
not.

**`class-boundary`** — a `pii-exposure` finding whose only leaked value is a
credential, key or config string must fail and be reclassified `info-disclosure`
(§8). Prevents the two classes double-counting the same response.

---

## 13. Pipeline

```
LOCAL="ollama/hf.co/huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF:latest"   # CONTEXT 131072
FB="opencode/deepseek-v4.1-flash-free"
MERGE="anthropic/claude-opus-5-5"
DRAFT="codex exec"
```

| Stage | Runner | Fallback |
|---|---|---|
| 0 — audit jsintel/jspackets/skillmap for the class boundary | none | — |
| 1 — source pack | none | — |
| 2 — draft | `codex exec` | `$FB` |
| 3 — adversarial review, cited JSON | `$LOCAL` | `$FB` |
| 4 — citation validation, rank, top 3 | none | — |
| 5 — merge + wiring | `$MERGE` | `codex exec` |
| 6 — gate: test suite | none | — |

### Pack contents

```
mind-hunt       hunt-pii-leak/SKILL.md  (all 112 lines — it is short and dense)
ARTEX           skills/api-security/SKILL.md Phase 9 (L104-110) + Phase 10 (L112-116)
                agent/promptcatalog.go L42-82
PortSwigger     /web-security/information-disclosure  (the channel taxonomy)
OWASP WSTG      sensitive-data and error-handling test procedures
BugVault        recon/fields.py  canary/trace  (the pii-boundary engine — essential)
                recon/har.py:28-34              (existing sensitive vocabulary)
                recon/extract.py:176 redact()
                recon/jspackets.py:21           (the info-disclosure ceiling, for §8)
                recon/skillmap.py               (the class boundary)
                .claude/skills/hunt-csrf/SKILL.md   (house template)
                integration contract
```

~26 KB ≈ 6,500 tokens ≈ **2.2 min of prefill**. Stable prefix first (house template,
integration contract), source excerpts last, so the llama.cpp prompt cache reuses it.

Configured: `providers.ollama.settings.headerTimeout` 1,800,000 ms (30 min),
`timeout` 3,600,000, `chunkTimeout` 300,000, `OLLAMA_KEEP_ALIVE=4h`.

### Stage 3 review contract

1. Which person-data surfaces or field categories does the draft miss?
2. Which blockers in §5 lack a defeat path, and which defeat paths are untested?
3. Where does the draft prove a leak with third-party data when a canary or an owned
   account would prove the same thing?
4. Where does the draft duplicate `hunt-js-bundle`'s `info-disclosure` territory
   instead of chaining to it?

```json
{"axis":"...","claim":"...","source_file":"...","line_start":0,"line_end":0,"why_missing":"..."}
```

Axes: surface inventory · field vocabulary · mask diff · boundary proof · control
defeat · channel coverage · denominator discipline · class boundary.

---

## 14. Build order

1. **`PERSON_FIELDS` + `classify_response` + `mask_state`** with fixture tests. Pure
   parsing, no network, and it is what every later step keys on.
2. **`recon pii trace`** wrapping `fields.trace()` — the `pii-boundary` case becomes
   available immediately because the engine already exists.
3. **The response-shaped seeding rule** (§8). Note this is `score.py`'s first
   response-keyed rule, so it may need a stored-response read path.
4. **`recon pii diff`** — API response versus rendered page. ARTEX Phase 9 #1, the
   highest-yield single check, and it needs the page and API responses already stored.
5. `recon/pii.py` ledger — schema, class, CLI, tests as four separate writes.
6. Chain rows (§7) and the `class-boundary` eval.
7. Blocker-defeat reference folder from §5.

Steps 1-4 use stored data and your own accounts only.

---

## Sources

- https://portswigger.net/web-security/information-disclosure
- https://github.com/OWASP/www-project-web-security-testing-guide
- https://github.com/BaaRai/ARTEX — `skills/api-security/` Phases 9-10, `notify/redact.go`
- https://github.com/b4rdia/HackTricks — no dedicated PII page; GraphQL traversal only
- https://github.com/vxcontrol/pentagi — own anonymiser only, no hunting method
- https://github.com/0xN0RMXL/BugBountySkills — `Information_Disclosure/` and
  `Sensitive_Data_Exposure/` both shells (4 domain markers per ~500 lines).
  **Eight folders read, eight shells.**
- mind-hunt (local, MIT, © 2026 MindflareX) — `skills/hunt-pii-leak/SKILL.md`
