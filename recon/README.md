# Recon: ARTEX-inspired, independently implemented

Runnable Python 3.9+ recon foundation, extending the existing BugVault engine. Deterministic collection and offline imports, not autonomous vulnerability exploitation. No ARTEX AGPL source was copied into this MIT implementation.

## Actual agents, skills and phases

| Component | BugVault implemented | ARTEX reference |
|---|---|---|
| LLM agents used by recon | **0** | 1 planner + configurable workers; default 3 workers = **4 ongoing instances**, plus a one-shot goals decomposer |
| Scheduling | **1 sequential deterministic scheduler**, **8 job handlers** | Event-driven LLM planner/frontier and concurrent workers |
| Recon skills | **8 repository capability guides** below; **0 automatically invoked LLM skills** | `api-recon` enabled for default workers; `bbot-recon`, `scopesentry`, browser support optional/configurable |
| External artifact adapters | **5 scanner formats + HAR** | BBOT events, ScopeSentry sync and live traffic extension |
| Model routing | Not implemented | Agent bindings/fallbacks configurable |

**All 18 BugVault skills live in one folder: `.claude/skills/<id>/SKILL.md`** at the repository root — the eight recon phase guides below plus ten hunting skills: five authentication skills (`hunt-auth-bypass`, `hunt-ato`, `hunt-mfa-bypass`, `hunt-oauth`, `hunt-saml`), `hunt-ssrf`, `hunt-idor`, `hunt-xss`, `hunt-sqli` and `hunt-csrf`. OpenCode and Claude Code discover that folder automatically in sessions opened inside this repository and offer a skill to the model when a task matches its description; verified with OpenCode 2.2.6, where a fresh session given a login `ato` row and asked to load the applicable skill, without being told its name, chose and loaded `hunt-auth-bypass`. The recon engine itself loads no skill. Qwen/GLM/OpenAI review agents are **not running**; credentials, endpoints, model IDs and a separate bounded review adapter would be required.

### Skill triggers and the request executor

- **Trigger:** `recon/score.py` seeds coverage rows for auth paths (login, signin, signup, register, password, reset, forgot, otp, mfa, 2fa, totp, verif, session, token, oauth, authorize, sso, saml, change-email, recover). `recon/skillmap.py` maps those classes to skills and `coverage.md` prints them in a `skill` column: `ato` → `hunt-auth-bypass`, `hunt-ato`; `mfa-bypass` → `hunt-mfa-bypass`; `oauth` → `hunt-oauth`; `saml` → `hunt-saml`. The hunter brief tells the agent to load the row's skill before testing; `@<skill-id>` in a prompt forces one.
- **Executor:** `python3 -m recon send <campaign> <url> [--method POST] [--json J | --form k=v | --data D | --data-file F] [--header 'Name: value'] [--no-follow]` sends one request through `ScopedClient`: scope per hop, `policy.allowed_methods`, mode, budgets, pinned egress, and the campaign `max_rps` enforced **across processes** through the `host_pacing` table (a shell loop of `send` cannot exceed it). It prints the `request_id` for `fact check`. Request header values are never stored; request and response bodies are stored as evidence. `Host`/proxy header overrides are refused.
- **Imported skills:** the five auth `hunt-*` skills are adapted from mind-hunt (MIT, © 2026 MindflareX; notice and source SHA-256 in each folder's `LICENSE.txt` and frontmatter). Full-keyspace OTP brute force, IP rotation through proxies, breach-corpus password spraying, real-user identities and references to skills outside the folder were removed; tests (`tests/test_recon_skills.py`) fail if any return. Cited H1 reference cases are checked against `vault/_data/reports-merged.csv`. OTP races use an operator-run Repeater parallel group, not unsynchronized Intruder concurrency; callbacks use Collaborator (MCP generation/polling tools available). A native burst executor and raw Burp evidence importer are not built. The shared workflow and fallback plan are in `.claude/skills/scope-policy/references/burp-workflow.md`; without permission, tools or adequate proof, park the lead. `hunt-ssrf`, `hunt-idor`, `hunt-xss`, `hunt-sqli` and `hunt-csrf` are original workflows, not imported auth skills.
- **Input census and injection hunting:** `recon inputs <campaign> --asset-id N` merges every observed input name with its locations, methods, accounts, sensitive-name flags, ID-likeness, coverage status and **stored-probe receipts** (which field names appear in stored request URLs/bodies), and states the header/cookie capture gap explicitly. `hunt-xss` maps per-field render contexts (HTML body, attribute, JS string, template, URL), classifies the filter/WAF rule with a one-probe-at-a-time ladder before any variant is designed, and covers reflected/stored/DOM/blind variants with marker-execution proofs; `hunt-sqli` proves injection with differential triples (probe, condition flip, negative control) across error/boolean/time/out-of-band/UNION/second-order variants, maps the detector first, and gates stacked/write probes behind program allowance. Neither dispatches payload wordlists or sqlmap; extraction proofs are minimal (banner or one test record).
- **CSRF action ledger:** `recon/score.py` seeds `csrf` rows for POST/PUT/PATCH/DELETE, for GET or method-unknown routes with a state-change verb (`/items/7/delete`, camelCase included) or action selector (`?action=`), and for `ws`/`wss` endpoints; `csrf` → `hunt-csrf`. See *CSRF: action × context × case ledger* below.
- **IDOR trigger:** `recon/score.py` seeds `idor-bola` rows from `id_params` captured by HAR imports (authenticated traffic with account labels) and GraphQL paths; `recon/report.py` `idor_candidates` builds the A/B comparison groups (same param name, different values per account) that `hunt-idor` tests with its staged ladder: direct marker swap → request-shape variants → vertical/cross-tenant → write proofs on disposable objects → chain targets via `finding link`. Live tests use the dedicated browser through Burp; adjacent-ID sampling stays on A/V-owned objects.

### SSRF: staged hunting workflow and offline evidence

`ssrf` coverage rows now name [`hunt-ssrf`](../.claude/skills/hunt-ssrf/SKILL.md).
Candidate triggers include nested/camelCase URL/URI fields and fetch/import/proxy/
webhook/feed-style paths; names are not fetch proof and discovery is not exhaustive.
The skill maps surfaces to their actual save/preview/delivery/render/worker triggers,
then progresses through 29 cases: baseline/control/attribution, blind/readable fetch,
outbound capabilities, parser/address/path forms, redirects, DNS/CNAME/rebinding,
renderers, internal/cloud boundaries, credential use and execution chains. Deep
branches (`dns`, `internal`, `cloud`, `credential`, `protocol`, `execution`) follow
`ssrf.depth_grants` in `scope.json`, copied from the program's written rules —
granted branches run at full depth with every destination still scope-checked, and
`chain_next` ranks the next proven edge (e.g. an observed cloud case immediately
promotes `credential-use`). Owned lab is the default without grants; an impact
ladder, credential-use ladder, metadata mechanics and internal-service triage are in
the skill references. It is not an autonomous exploit runner or payload dump.

```bash
python3 -m recon ssrf plan acme --asset-id 12 --context context.json
python3 -m recon ssrf record acme --asset-id 12 --context context.json \
  --case attribution --state blocked --note "Browser tools not connected"
python3 -m recon ssrf status acme --asset-id 12 --context context.json
python3 -m recon ssrf correlate acme --asset-id 12 --bundle bundle.json
```

These commands send **no traffic**. Context is exactly `request_url`, `method`,
`account`, `role`, `tenant`, `workflow`, `field`; the exact URL is scope/family-checked
and variants are not pooled. See [evidence schema/examples](../.claude/skills/hunt-ssrf/references/evidence.md).
Record appends snapshot-bound events, retaining stale history, and copies <=8 private
campaign-local artifacts (<=5 MB each) by hash. `observed`/`negative` need distinct
replay/control hashes and a declared request count, not a code-certified exploit.
Status checks latest artifact integrity. Outcomes remain operator assertions;
three attempts are a per-case effort cap, never endpoint-wide SSRF completeness.

Correlate accepts only a normalized schema-1 bundle, not arbitrary raw Burp/Collaborator
exports. It checks exact context, SHA-256, granted callback hosts, attempt markers,
<=600-second windows, duplicate IDs and origin/protocol filters. Independent response
canaries must be absent from request/control. It reports DNS/HTTP/byte observations,
not certified application attribution, unauthorized impact, native facts or finding
promotion. Input <=1 MB, <=2,000 events, <=25 MB unique referenced artifact data.

Live work still requires the **connected dedicated visible browser through Burp**;
missing browser tools/CA/capture blocks execution, not permits an alternate client.
Burp is not native scope/rate/budget-enforced. Declared ledger counts are not measured
traffic or shared budget reservations, and branch gates require manual verification.
Apply replay, distinct negative control and the existing four-question reportability
gate; park inconclusive/no-impact work with evidence intact.

Both supplied repositories are pinned in [sources.md](../.claude/skills/hunt-ssrf/references/sources.md).
The 2023 HackTricks fork is CC BY-NC 4.0; prose/payload tables were not copied. The
second MIT knowledge base mixes XSS concepts, placeholders and inconsistent bounty
claims; those were not imported as verified findings. Cloud prerequisites were checked
against current AWS/GCP/Azure vendor documentation.

### CSRF: action × context × case ledger

`csrf` coverage rows name [`hunt-csrf`](../.claude/skills/hunt-csrf/SKILL.md). The unit
of CSRF coverage is the **action**, not a field: `recon/csrf.py` reconciles one action
per endpoint family × method × selector from captures, endpoint operations, forms
(method, enctype, token field names), JS, sourcemaps and OpenAPI declarations
(request types, security schemes). Fieldless actions, GET mutations, each GraphQL
mutation (named in client code or captured — captures carry the operation type and
name, never the document or variables) and `ws`/`wss` handshakes are actions of their
own; plain reads and inferred version siblings are not. Each action has **contexts**
per representation × authority (cookie, browser-managed Authorization, explicit header)
× account/role/tenant/workflow; a declared context is superseded once the action is
captured. Every scheme/host/port is its own inventory, so nothing pools across origins.

```bash
python3 -m recon csrf sync acme                      # idempotent inventory; sends nothing
python3 -m recon csrf plan acme --action 12          # contexts, 15 case cards, readiness, open variants
python3 -m recon csrf record acme --context 31 --case cookie-delivery --variant top-level-post \
  --state observed --initiator cross-site --initiator-origin https://attacker-lab.example \
  --delivery form-post --browser "Chrome 131" --artifact before=ev/b.json \
  --artifact after=ev/a.json --artifact request=ev/req.txt
python3 -m recon csrf status acme --host app.acme.com   # per-origin open/observed/stale, gaps, coarse conflicts
python3 -m recon csrf verify acme                    # re-hash every recorded artifact
```

All commands are offline: no HTTP, browser, scanner or finding promotion. Cases follow
`baseline → attack families → effect-handoff`; the plan names why a family does not
apply (`n-a-suggested`), and contexts whose capture shows no credential (sanitized HAR
exports drop cookies) stay `needs-confirmation` instead of silently closing. The record
path encodes the design decisions from `hunt-csrf/references/evidence.md`: `observed`
compares differing before/after readbacks, attack cases follow an observed baseline and
come from a browser initiator on another origin, replays carry initiator `none`, a
denied preflight cannot be observed, same-site initiators name their prerequisite,
realtime observations include the protected messages, and a case-level `negative` waits
for every applicable variant. Each event stores the context's facet hashes (tokens,
headers, cookies, origin metadata, request shape): a later capture reopens only the
cases depending on a changed facet. `csrf.per_case_effort_cap` (default 3) is effort
per case and context. Coarse `cov` rows never close open action cases; `coverage.md`
carries the per-origin CSRF table and the next cases.

HAR and Burp imports keep value-free capture metadata per observation
(`recon/csrfmeta.py`): request MIME, authority mechanism and Authorization **scheme**,
anti-CSRF token channel names, constant custom-header flags, Origin and Referer
**origins** (paths/queries dropped), Sec-Fetch values, Set-Cookie names with SameSite
(explicit versus omitted), Domain, Path, Secure, HttpOnly and prefixes, and GraphQL
operation type+name. Cookie, header and token values are never stored.

`tests/test_recon_csrf_browser.py` is an owned-loopback, two-origin Chromium lab (three
lab hostnames resolve to 127.0.0.1 through Chromium host-resolver rules; every other
hostname is forced to fail). It checks the mechanics the case families rely on, then
records the real outcomes through the ledger: Lax withheld on cross-site POST but sent
to same-site siblings and on cross-site top-level GET; Strict sent to siblings and
withheld on cross-site GET; a 200 error envelope with an unchanged readback; lenient
versus strict text/plain JSON parsing; a constant custom header refused at preflight
(the POST never leaves the browser); and a simple credentialed fetch whose response is
unreadable while the write is delivered. On Chromium 148 a fresh cookie **without**
SameSite was attached to a cross-site top-level POST while explicit Lax was not — the
reason omitted and explicit SameSite stay separate in the ledger.

### Explicit method grants and shared Burp MCP

PUT, OPTIONS and DELETE are supported alongside GET, HEAD, POST and PATCH. Defaults
remain read-only in every mode. To grant all seven when the written program rules
permit them, initialize a **new** active campaign with:

```bash
python3 -m recon init acme-auth --seed https://app.example.com --mode active \
  --allow-method POST --allow-method PUT --allow-method PATCH \
  --allow-method OPTIONS --allow-method DELETE
```

For an existing campaign, edit `policy.allowed_methods` to
`["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"]` and use active/loud
mode, removing forbidden methods. `init` never overwrites an existing config. A method
grant does not itself send a request; OPTIONS advertising a method is not permission
to use it. PUT/DELETE tests must use disposable operator-owned resources. Tests verify
the added methods are individually granted, scope checked, recorded and never
automatically redirected.

Writes and scanners are **campaign-permission based, not blanket-banned**.
State-changing tests require the program's written allowance and the applicable
method grants, disposable operator-owned test resources, before/after evidence
and agreed cleanup. Operator-run scanners require a standing campaign execution
plan: record the grant/source in `scope.json`'s `rules` and the tool/version, exact
targets/exclusions, checks, methods, rate/concurrency, request cap, time window and
stop conditions in the campaign's private `.recon/`. Approved actions within those
limits need no repeated exception; tool approval prompts still apply. The dedicated
browser/Burp remains the default unless the plan separately permits another path.
These are operator-reviewed instructions, not new config switches or an external
scanner adapter: external scope/method/rate/shared-budget accounting is manual,
and a failed policy check cannot be bypassed. See
`.claude/skills/scope-policy/SKILL.md`. No scanner is installed or launched by this policy.

`opencode.json` registers `burp` at `http://127.0.0.1:9876/mcp` for **every tool-capable
model selected in this project**, with no provider-specific override. `.mcp.json` is
the native Claude Code equivalent (one-time project approval in `claude` still needed).
`AGENTS.md` and `CLAUDE.md` share the project instructions. Live proxy HTTP/WebSocket
history, Organizer items and scanner issues are available through the same server;
campaign files remain the shared durable evidence store across independent sessions.
Raw traffic may contain credentials: read only relevant bounded pages and do not
broadcast everything to all providers.

Verified on 2026-11-12: loopback-only Burp MCP `burp-suite` 1.1.2, 27 advertised tools,
OpenCode connected, and a successful pure local URL-encoding call. No target requests
or history dumps were made during setup. Direct HTTP needs no proxy JAR; a checksum-
pinned local copy is in `tools/burp/` for stdio-only clients, with no runtime dependency
on its original download.

Burp MCP does **not** enforce recon scope/rate/budgets or mint native response IDs.
Read-only history and local codecs are available; active sends, Repeater/Intruder
preparation, config changes and Collaborator generation/polling require approval.
The current MCP can create tabs but cannot send a synchronized Repeater group or run
an Intruder attack. `jku`/`x5u` key trust needs a server returning the chosen JWKS or
certificate; a callback alone proves neither login bypass nor a completed chain.

Operator-confirmed payload-model preference: **DeepSeek V4.1 Flash primary**, with an optional second fallback slot. The alternate model is not yet specified; no replacement is guessed. This records the intended order, not a live router or provider adapter. Any future fallback must retain requested/actual model attribution and cannot bypass failed scope, evidence, context or budget gates.

| Phase / guide ID | Tools and handlers | Data produced |
|---|---|---|
| `scope-policy` | scope checks, mode and budget gates | Operator-controlled authorization; never widened by discoveries |
| `passive-discovery` (L0) | `crtsh`, `wayback`; offline subfinder/BBOT | Hostnames, historical URLs, archive references |
| `service-mapping` (L1) | `probe`, stdlib DNS/HTTP, optional `dig`; httpx/ScopeSentry imports | IP/name associations, origins, fingerprints; imported claims labelled separately |
| `static-api-mapping` (L2) | `wellknown`, `jsharvest`, `jsparse`, `mapparse`; Katana import | Endpoint families, methods, parameter names, JS/chunks/maps, frontend routes |
| `apk-static-mapping` (L3 mobile) | External REA/JADX static APK analysis (manual workflow, `docs/rea-analysis.md`) | Mobile-only endpoints, pinned old API versions, embedded secrets, deep links — untrusted leads |
| `synthetic-ui-mapping` (L3) | `runtime`, optional Python Playwright + Chromium | Synthetic UI/client-attempted API surfaces, not backend access |
| `captured-auth-mapping` (L4) | Offline HAR import | Account × role × tenant × workflow observations |
| `inventory-handoff` | Local scoring/reporting | `recon.md`, `coverage.md`, `intel.md`; unvalidated leads |

These are capability phases, not eight always-running agents or a rigid completion barrier. New assets enqueue dependent jobs; imports/reporting are explicit commands. `max_jobs` limits queue work, not HTTP request count.

## Usage

```bash
python3 -m recon catalog                         # all tool integrations + local PATH availability
python3 -m recon catalog --json                  # machine-readable phases, counts, guides, tools
python3 -m recon init acme --seed https://app.acme.com --mode passive
# Edit scope.json from WRITTEN program rules. Seeds do not authorize subdomain wildcards.
python3 -m recon check acme https://app.acme.com/api/orders
python3 -m recon run acme --max-jobs 100
python3 -m recon import acme subdomains.txt --format subfinder
python3 -m recon import acme bbot.jsonl --format bbot
python3 -m recon import acme httpx.jsonl --format httpx
python3 -m recon import acme katana.jsonl --format katana
python3 -m recon import acme scopesentry.json --format scopesentry
python3 -m recon import-har acme alice.har --account alice --role member --tenant a --workflow-state draft
python3 -m recon import-har acme bob.har --account bob --role member --tenant b --workflow-state draft
python3 -m recon import-burp acme burp-export.xml --account alice   # header/cookie NAMES only; responses stored for marker tracing
python3 -m recon import-burp acme raw-request.txt --scheme https    # one raw request; Host header supplies the origin
python3 -m recon import-openapi acme api-spec.json                  # OpenAPI 3 / Swagger 2 declared fields; never fetched
python3 -m recon fields sync acme --asset-id 12                     # ledger rows: field x location x account x case
python3 -m recon fields record acme --asset-id 12 --field q --case xss-reflected --state observed --model deepseek-v4.1-flash
python3 -m recon fields canary acme --asset-id 12 --field bio       # mint bv_ marker; submit via the real workflow, then:
python3 -m recon fields trace acme --marker bv_1a2b3c4d             # propagation map over stored captures
python3 -m recon fields matrix acme --module orders                 # trigger-matrix completeness (list/search/filter/create/edit/bulk/export/sort)
python3 -m recon fields claim acme --module orders --state full     # refused while cells are missing
python3 -m recon waf plan acme --host app.acme.com                  # bounded single-then-pair probe sequence
python3 -m recon waf observe acme --host app.acme.com --element '<' --marker m1 --baseline-status 200 --probe-status 403
python3 -m recon waf record acme --host app.acme.com --element '<' --outcome blocked --location form
python3 -m recon fields packet acme --asset-id 12 --field bio --case xss-stored   # refuses incomplete context
python3 -m recon fields payload acme --file packet.json --model deepseek-v4.1-flash  # authorship attribution
python3 -m recon fields blind acme --asset-id 12 --bundle blind-bundle.json       # shared callback-validation primitives
python3 -m recon chain realism acme xss-admin-ato downstream pass --note "server-side authz verified on the admin object"
python3 -m recon status acme
python3 -m recon report acme
```

Imports and reports are **offline**. Imported assets may enqueue jobs, but only a subsequent explicit `run` executes them, under its scope/mode. A malformed-record import returns exit code 2 with counts and bounded redacted error locations. Invalid file envelopes/size fail before import registration. Never treat every file called JSON as a supported export; schemas are listed below.

### Findings, exploit lookup and agent briefs

```bash
python3 -m recon lookup acme                     # recorded versions -> bounded exploit lookup + KEV leads
python3 -m recon finding add acme --title "IDOR on invoices" --class idor-bola --url https://app.acme.com/api/invoices/7
python3 -m recon finding move acme 3 confirmed --replay replay.txt --control control.txt
python3 -m recon finding move acme 3 impact-proven --impact impact.txt --severity high
python3 -m recon finding link acme 2 yields-token 3        # chains appear in findings.md
python3 -m recon finding move acme 3 reported --report report.md
python3 -m recon finding move acme 3 duplicate --note "dup of #2345678"
python3 -m recon brief acme                      # agents/hunter.md, validator.md, reporter.md
python3 -m recon lookup acme --refresh            # explicitly retry cached/suppressed providers
python3 -m recon recall acme "tenant draft export" # offline source-linked lexical recall
python3 -m recon plan acme --asset-id 12          # bounded planning context; no model calls
python3 -m recon plan acme --proposal proposal.json          # validate only
python3 -m recon plan acme --proposal proposal.json --apply  # enqueue only, never execute
```

- **Stages** (`recon/findings.py`): `lead → confirmed → impact-proven → reported → accepted | duplicate | informative | n-a`, or `killed` with a reason. `confirmed` is refused without a replay artifact **and** a different negative-control artifact. Artifacts are copied to `.recon/evidence/` by SHA-256. The tool records them; judging them is the validator's job. Stage changes update the matching coverage row (`lead` → queued, `confirmed`, `killed` → refuted). Findings are only accepted for in-scope URLs.
- **Links and chains:** relations `yields-token`, `yields-id`, `yields-access`, `authenticates-to`, `escalates-via`, `pivots-to`, `enables`, `same-root-cause`, plus lineage `spawns`, `derived-from`, `proves`. `findings.md` lists linked chains plus *chain hints*: unlinked findings on one host whose classes commonly combine (open redirect + OAuth, XSS + CSRF, IDOR + ATO, …).
- **Chain todolist** (`recon/chain.py`, `recon chain status|add|realism`): ARTEX's shared-todolist idea made deterministic — built-in chain templates (derived from the hint table plus multi-step redirect→OAuth→ATO, IDOR→reset→ATO, SSRF→metadata→credential, XSS→admin→ATO, HTMLi→token→ATO, SQLi→authbypass→admin, SSTI→code-exec chains) and validated custom chains (2..8 unique steps, ≤20 per campaign). Every step resolves offline from the findings store: `proven` means a finding of that class reached `confirmed` or later (replay + negative control already enforced), `ready` is actionable, `lead-open` names an unconfirmed lead to confirm, and a class whose findings all died is a `failed` pivot that `blocks` the rest and parks the chain — without refuting sibling findings. The **realism gate** (plan §6) adds three mandatory questions (`reachable`, `preconditions`, `downstream`) on every completed chain: with all steps proven but answers missing or failed, the chain is parked with the failing question named — the impact claim needs evidence-backed answers first. The overview ranks ready chains first, flags unlinked consecutive proven steps for lineage hygiene, and `findings.md` embeds the todolist. It orders the hunt; it never executes, widens scope or promotes findings.
- **Outcome log:** every transition is a `finding_events` row with class, severity and tech. This is the raw history for a later "what worked for me" ranking. No ranking is built from it yet.
- **Exploit lookup** (`recon/vulnintel.py`): sends **no target request**. Versions come from responses `run` already recorded (Server/X-Powered-By/X-Jenkins headers, CMS generator tags, Confluence/GitLab/Grafana markers, JS library banners) and from imported httpx `tech`. Searches: local `searchsploit` (if installed; product+version and product-only, so range titles like `< 3.5.0` are found), Sploitus (JSON POST of `"<product> <version>"` only; refused if the payload names an in-scope host), and the CISA KEV feed (cached 24 h in `.recon-cache/`). Exploits are kept only if the title names this version or a range containing it. CMS plugin/theme advisories are dropped. Priority: exploit for a KEV CVE +5, KEV product match +2, exact version +3 / range +2, remote/webapp +1, server-side +1, client-side library −4. Each lead stores a precondition checklist: version evidence, reachability, payload-free check, then a minimal proof.
- **Agent briefs** (`recon/brief.py`, templates in `recon/prompts/`): all three roles receive operator preapproval bounded by `scope.json`, mode, rate and attempt budgets, `rules` and `excluded_bug_classes`. They need not repeatedly ask for already-approved actions. This is not blanket permission for new targets or arbitrary actions. Prompts explicitly distinguish the scoped HTTP client from unsandboxed shells, instruct against bypassing policy, and treat target/advisory/recall content as untrusted data. These files do not launch agents or implement model-family separation. Rules/excluded classes are instructions, not a general natural-language policy engine. The hunter explicitly invokes `lookup` and `recall`; the validator distinguishes positive controls from negative security assertions and file-hash gates from semantic validation.

### Bounded reliability, recall and optional planning

- **Lookup fallback** (`recon/reliability.py`): SearchSploit first, then Sploitus if no relevant local result or expected source failure; KEV remains separate enrichment. At most two attempts per configured provider. Policy/budget errors stop the chain instead of trying another path. This is not a general search engine/model fallback router, and the first useful source may not include all other providers' results.
- **Recovery and stall suppression:** provider attempts are written before execution; interrupted attempts are identified on the next uncached retry. Successful/empty results recover from SQLite for one hour; failed rounds cool down for 30 seconds, and three consecutive failed rounds suppress that provider/query for one hour. `lookup --refresh` explicitly retries cached/suppressed sources. CLI/schema/transport errors are distinct from clean empty results; incomplete lookups are counted as unresolved. This does not implement parallel job leases, arbitrary-agent loop detection, or automatic repair of executables.
- **Provenance-linked recall** (`recon/recall.py`): campaign-local lexical ranking over at most 5,000 records, with row references, import/record links, evidence basis and canonical row-snapshot hashes. No embeddings, cross-campaign sharing, raw response-body indexing or model calls. Truncation is explicit; this is a deterministic baseline, not PentAGI-style semantic/causal memory.
- **Optional planning boundary** (`recon/planning.py`): export at most 100 asset snapshots and review externally supplied JSON proposing at most 20 known-handler intents. All intents validate before queue writes; current scope/config and asset hashes must match, handler/asset/mode must be compatible, and arbitrary commands/new targets/extra fields are rejected. `--apply` only enqueues unique jobs; a separate explicit `run` is required. No Qwen, GLM or OpenAI provider adapter is implemented or called. Snapshots contain private campaign context: do not upload them without operator approval.
- **Remaining caveats:** lookup versions/ranges remain heuristic; product-level KEV matches explicitly lack version applicability proof. Killing one hypothesis no longer refutes a sibling live finding. Findings require a scope anchor, but stage gates still need a human or independently configured validator to judge artifact meaning. SQL/transport hardening is not independent exploit validation.

### Deterministic response-backed facts

`recon/factcheck.py` checks concrete predicates against a specific stored HTTP response, rather than accepting an arbitrary statement merely because it cites a response ID:

```bash
python3 -m recon responses acme --limit 20
python3 -m recon fact check acme --response 12 --predicate '{"type":"status_is","expected":200}'
python3 -m recon fact check acme --response 12 --predicate '{"type":"header_present","name":"Content-Type"}'
python3 -m recon fact check acme --response 12 --predicate '{"type":"body_contains_raw","marker":"<BV_CANARY_123>"}'
python3 -m recon fact verify acme 3
python3 -m recon fact context acme 1 2 3
```

- Supported types: `status_is`, `header_present`, `header_equals` (exact stored string), `body_contains_raw` (exact UTF-8 bytes). Header names ignore case; header values and body sequences do not. Extra fields such as a free-text `claim`, arbitrary regex or executable checks are rejected. Claims are generated by code and refer only to that recorded response, not every member of an endpoint family.
- Results: **supported**, **contradicted**, **inconclusive**, **stale**. Check/verify return exit 2 unless supported. Incomplete or legacy captures cannot prove a missing marker is absent from the whole response. An exact match in a captured prefix can support narrow byte presence. Compressed bodies are not decoded; unsupported encoding, unavailable/corrupt body data, or bodies over the 5 MB verification limit are inconclusive. HTML entities, URL encoding and JSON escapes are never decoded to manufacture a raw match.
- Native HTTP replies now expose `request_id` and persist capture completeness/basis. Typed definitions are deduplicated by response snapshot and predicate, with separate verification events. Rechecks compare metadata/context snapshots and verify body length/SHA-256 when checking bytes. Changed scope/binding or metadata invalidates old checks. No network requests are sent during verification.
- `fact context` accepts 1–20 explicit fact IDs and rechecks all of them; it refuses export if any is not supported. It exports only code-generated predicates/claims, not arbitrarily labelled narrative facts. This is a building block for a future context gate: there is still no model call, payload-task completeness policy, cloud-sharing approval, or automatic hypothesis/ownership validation. Bundles remain private campaign data.
- Reports and recall distinguish typed results from old narrative `observed`/`inferred` labels (`verification=not_machine_checked`). Native headers are the recorded header-map view, not a byte-complete HTTP transcript; a matching header or status proves only what that stored record says. Hashes detect mismatched changes, not a malicious database owner or forged capture. Historical responses do not prove current live behavior.
- **A raw marker match is not proof of reflection causality, executable HTML, XSS, cross-account access or business impact.** Those still need context-specific replay, controls and independent validation. These checks never promote finding stages or coverage to confirmed.

### Complete tool inventory and integration status

`catalog` is the executable source of truth (`recon/catalog.py`); it checks PATH/package presence without executing tools or contacting services.

- **Native:** crt.sh, Wayback CDX, stdlib HTTP/DNS/HTML/JS/source-map extraction and fingerprint signatures.
- **Optional native:** `dig` for CNAME lookup; Python Playwright and installed Chromium for opted-in synthetic browsing.
- **Offline adapters only:** BBOT, subfinder, ProjectDiscovery httpx, Katana, ScopeSentry; HAR from browser DevTools/Burp/Caido.
- **Manual only, no executor/adapter:** Nmap and ffuf. REA (reverse-engineering MCP/CLI, `npx rea-agents`) with its JADX and adb providers — static APK/JS/.NET/binary analysis workflow documented in `.claude/skills/apk-static-mapping/SKILL.md` and `docs/rea-analysis.md`; no import adapter until a real export schema is pinned.
- **ARTEX reference, not integrated:** dnsx Go enrichment library; BBOT modules wafw00f, paramminer_getparams, sslcert, gowitness; Playwright MCP/CLI; ARTEX capture extension. ARTEX scripts harvest_static.py, spider_mpa.py, extract_route_map.py, build_perm_tree.py, preload.js and runtime_harvest.js are references, not installed tools here.
- **Outside recon, never dispatched:** Nuclei, Dalfox, sqlmap, BBOT lightfuzz. Do not equate scanner output with confirmed vulnerabilities.
- **ARTEX shell support, not invoked here:** curl, wget, whois, ping, netcat, telnet. General shell/developer utilities are not recon integrations.

No external scanner is automatically installed or launched. A matching PATH name is not version/vendor verification (especially Python's unrelated `httpx` CLI). ScopeSentry exports work without a deployed service; there is **no** live ScopeSentry MCP/API adapter. Fingerprint-to-tool-pack suggestions are backlog labels, not installed tools or separate agents.

### Supported external artifact records

All scanner adapters accept JSON arrays or JSONL; subfinder additionally accepts one hostname per line. ScopeSentry expects a JSON list or unambiguous `data` / `list` / `items` / `results` wrappers up to three levels deep.

| Format | Accepted surface subset |
|---|---|
| BBOT | `type` + `data`: DNS_NAME, IP_ADDRESS, URL, URL_UNVERIFIED, HTTP_RESPONSE (`data.url`), OPEN_TCP_PORT |
| subfinder | Plain hostname or `{"host":"api.example.com"}` |
| httpx | `{"url":"https://api.example.com","method":"GET","status_code":200,"tech":["nginx"]}` |
| Katana | `{"request":{"endpoint":"https://api.example.com/api/items","method":"GET"}}` |
| ScopeSentry | `url`, or `subdomain` / `domain` / `ip` / `host`, optionally `port`; finding/risk records ignored |
| HAR | `log.entries[].request` and response status/MIME, plus value-free CSRF metadata (MIME, authority, token channel names, Origin/Referer origins, Set-Cookie attributes, GraphQL operation names); no replay and no raw bodies imported |
| Burp export (`recon import-burp`) | "Save items" XML (base64 request/response), `requests`/`items` JSON lists, or one raw HTTP request (`--scheme http|https`). Header/cookie **names** captured, values dropped; stored responses (basis `imported-burp-capture`) are searchable by `recon fields trace` |
| OpenAPI/Swagger (`recon import-openapi`) | JSON OpenAPI 3 `servers[].url` or Swagger 2 `host`/`basePath`; path×method operations with parameter (`query`/`path`/`header`/`cookie`) and JSON body schema leaf fields as `spec_fields` |

Imports are bounded to 25 MB and 50,000 records. Unknown BBOT event types are counted as unsupported. Imported metadata is untrusted tool output, not a fresh server measurement. No vulnerability table is populated. Export-version compatibility beyond these subsets is not claimed.

## Data categories and overlap prevention

| Layer | Identity / merge rule | What stays separate |
|---|---|---|
| Typed assets | SQLite unique `(kind, value)`; normalized URL origins, hosts/IDNA and default ports | Schemes and nondefault ports; frontend routes vs endpoints vs JS/maps; out-of-scope intel |
| Endpoint families | Origin + path with numeric/UUID-like IDs grouped; query values removed | **Scheduling group only**, not semantic equivalence |
| Operations | Unique `(endpoint_family, HTTP method)` | GET vs POST vs DELETE; UNKNOWN remains unknown |
| Exact variants | `(family, method, original path, sorted query names)` | Numeric IDs, trailing slashes, path case and query-name variants survive family grouping |
| Sources | Source lists union; import `(format, SHA-256 of original bytes, context)` | Same asset can have many source/import records; renaming files does not create a new import |
| Provenance | Unique `(asset, import, record index)` | Different sources and distinct original records retained; raw scanner bodies/credentials not copied |
| HAR samples | Unique capture `(import identity, entry index)` | Account, role, tenant and workflow labels are part of import identity; repeated same file/context does not inflate samples |
| Observation basis | Union list plus context/provenance, not a last-writer-wins label | Static references, synthetic UI, attempted requests, captured real traffic and imported tool output never become confirmation |
| Job queue | Unique `(handler, asset)` | Explicit reruns; skipped jobs can requeue when policy permits |
| Facts and coverage | Observed/inferred facts; coarse family × bug-class backlog | Recon does not mark vulnerabilities confirmed |

List summaries cap at 200 items, but exact variants and import provenance are separate rows. Re-serialized captures have a different content hash and are treated as new captures; there is no unreliable global semantic deduplication of all traffic. Old databases retain original tables; newly added operations/variants apply to newly observed/reimported endpoints. Legacy samples without capture identity cannot be retrospectively deduplicated. Family grouping can conflate distinct behavior: consult exact variants and original captures before testing.

Reports show parameter presence, not proven required/optional rules. Priority scores do not establish other hunters' testedness or guarantee no duplicate reports. Coverage remains a **coarse backlog**, not full method × role × tenant × ownership × workflow × security-test assurance. User-entered `cov confirmed` is not independently verified validation.

Context-specific parameter tables do not pool different accounts/roles/tenants/workflows. Explicit comparison groups require the same known role and workflow plus distinct account/tenant principals; they link observation IDs rather than declaring IDOR. Legacy aggregate tables are clearly labelled non-equivalent. New HAR observations retain import/record/path references and, when supplied, a hash of the original HAR response `text` representation (not a decoded wire-body equivalence or authorization verdict). Already deduplicated legacy samples are not silently rewritten; a separate explicit migration would be needed to backfill missing capture metadata.

## Execution boundaries and remaining limits

- Explicit URL scope rules retain scheme/port/path case; exclusions conservatively ignore path case. Bare hostname/CIDR rules intentionally allow all ports. Exclusions win. URL userinfo and Host/proxy header overrides are rejected. Discoveries never edit `scope.json`.
- Target HTTP methods are granted by `policy.allowed_methods` (default GET/HEAD; POST/PUT/PATCH/DELETE/OPTIONS are an explicit operator grant, rejected in passive mode) and checked per redirect. Write methods never auto-follow redirects — the 3xx is returned so a payload is never re-sent elsewhere — and their request bodies are stored and hashed like response bodies (`request_payload` table). Cross-origin redirects drop custom headers; passive providers never receive target authorization headers. `ScopedClient.request()`/`post_json()`/`post_form()` are the write-method API; every request stays scope-, rate-, budget- and egress-checked.
- Target and passive HTTP share `policy.max_requests` (default 1000) and `max_seconds` (default 600) per Recon process/instance, plus a persistent `max_campaign_requests` (default 10000) counter reserved before sends, including failed attempts. Existing logged requests initialize legacy campaign usage. Raising the cap is an explicit operator config change, not an automatic reset. Connection outcomes and resolved/pinned peers are recorded in `connection_events`. Rate limits remain per host. Socket timeouts are bounded, but DNS/slow reads can overrun a soft deadline; this is not a hard process sandbox. `dig` has its own timeout.
- Runtime is disabled unless `runtime.enabled=true`. All real browser HTTP reads use the shared scoped client; no `route.continue_()` target bypass. Unsupported WebSocket interception fails closed. API requests are mocked unless live GET is explicitly enabled. Browser cookies/storage are synthetic rendering aids, not replayed credential sessions; use HAR for real authenticated mapping.
- **Built-in HTTP connections now validate and pin DNS answers** (`recon/egress.py`). A whole mixed public/private answer set fails closed; each connection uses a validated numeric sockaddr without a second DNS lookup and checks the connected peer. HTTP Host and TLS SNI/verification retain the original hostname. Nonpublic DNS results require explicit `policy.allowed_ip_ranges`; an in-scope numeric private address is an explicit lab/internal grant. `denied_ip_ranges` and scope IP/CIDR exclusions take precedence. Intel providers require globally routable addresses even when target private ranges are allowed. Configured proxies fail closed until a separately audited proxy path exists.
- **This is not OS/container-wide egress enforcement.** It covers built-in HTTP clients and browser HTTP reads, not arbitrary shells, SearchSploit executables, DNS utilities, external scanners, non-HTTP browser channels (e.g. WebRTC), network routing/NAT or model providers. No firewall is installed, no autonomous scanner runner is enabled, and DNS lookups themselves are not pinned/contained HTTP traffic. Independent egress isolation is still required before unrestricted subprocess agents.
- GET can change state on poorly designed applications; URL scope and method restrictions do not guarantee no side effects. Review excluded paths. No automatic credential login, exploit/fuzzer execution, port scan, or account mutation is included.
- Static extraction is heuristic: full dynamically constructed webpack/Vite manifests, arbitrary API base URLs and parameter semantics are not reconstructed. Collection is bounded, not complete.
- URL seeds now retain exact entry paths. Root well-known probing is skipped under narrow path grants, not used to widen them. HTML collection can follow same-origin, in-scope nonstatic/non-API links under `collection.max_pages` (default 1, maximum 100) and `max_depth` (default 2, maximum 5); forms are only mapped, not submitted. Set a larger page limit explicitly only when permitted. Redirect hops also consume HTTP budgets, so the page cap is not a request cap. Dynamic URLs and misleading API-looking/HTML routes remain heuristic gaps; there is no automatic credential login or arbitrary API crawl.
- Single sequential scheduler only; do not run multiple processes against the same campaign. No adaptive LLM planner, parallel worker leases, paid-model routing or live capture extension yet.
- `.recon/` includes raw downloaded target responses and response headers; they can contain secrets. HAR imports omit header/cookie values and bodies, but paths/IDs/labels can still be sensitive. Keep campaign artifacts private and encrypted as needed; original HAR exports are outside this tool's sanitization guarantees.

For synthetic browsing, use an existing environment or install optional dependencies yourself, then enable runtime after reviewing scope:

```bash
python3 -m venv .venv
.venv/bin/pip install 'playwright>=1.48'
.venv/bin/python -m playwright install chromium
.venv/bin/python -m recon run acme
```

## Verification and attribution

```bash
python3 -m unittest discover -s tests -v
# Includes the owned-loopback browser test when package + Chromium are installed:
.venv/bin/python -m unittest discover -s tests -v
```

All **363 tests pass** in `.venv`; system Python runs 363 with the two optional Playwright
tests (runtime harvest, CSRF two-origin lab) skipped. Tests use offline fixtures and owned
loopback servers, not bounty targets or model APIs. The 40 SSRF tests include exact-context/stale ledgers, grants,
artifact boundaries, false-positive controls and a bounded vulnerable-vs-fixed fetcher.
They do not test arbitrary cloud/protocol chains or certify live browser capture.

Three text-only SSRF skill scenarios were run with/without the skill. Saved outputs,
narrow explicit-text checks and the static review viewer are in
`.recon/skill-evals/hunt-ssrf/iteration-1/review.html`. Results are 12/12 versus 6/12
checks, largely reflecting integration details unavailable to the baseline, not a
statistical detection benchmark. Timing/token data were unavailable. The eight recon
phase guides have structural/code-reference tests, not behavioral benchmarks.

Small reserved-domain fixtures live in `tests/fixtures/recon/`. To exercise every adapter offline, initialize a disposable campaign with no seeds and `in_scope: ["example.com", "*.example.com"]`, import the five scanner files, then import `alice.har` and `bob.har` with different account labels. Importing Alice twice with the same labels must retain two total HAR samples, not three. Do **not** run the queued fixture assets against example.com; they are synthetic, not authorization.

Architectural reference: [ARTEX at 9bf5d816](https://github.com/BaaRai/ARTEX/tree/9bf5d816aeb361d79de874fcdbeeb0de31bd83f2), especially planner/worker separation, api-recon, bbot-recon, asset/exploration graphs and traffic capture. ARTEX is AGPL-3.0; this code uses independently implemented ideas, not copied scripts or prompts.
