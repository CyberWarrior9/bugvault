# Handover — BugVault Setup

> Complete guide to this repository as of **2026-11-12**. Written for someone
> (human or agent) taking over the project cold. Read this top to bottom, then
> `recon/README.md` for the deep recon detail, then `docs/model-routing.md` for
> the model policy.

---

## 1. What this project is

BugVault is an **authorized bug-bounty hunting knowledge base and recon engine**:

- A git-versioned Obsidian vault (the "AI context layer") built on HackerOne's
  disclosed-reports dataset — 15,443 unique report IDs, 85 study dossiers.
- A runnable, **scope-enforced recon engine** (`recon/`) that maps attack surface
  deterministically: 1 sequential scheduler, 8 job handlers, 0 LLM agents.
- A finding lifecycle with hard evidence gates (replay + negative control).
- Design plans (plans 1–4) for the full hunting platform that is **not yet built**.

**Scope of everything in this repo: authorized targets only** — bug bounty
programs, owned labs, contracted engagements. Nothing here is for unauthorized
testing.

## 2. Current status (honest)

| Capability | State |
|---|---|
| Test suite | **363 tests passing** in `.venv` (incl. the loopback runtime and two-origin CSRF browser tests); system Python skips those two optional Playwright tests |
| Ready for | Owned local demo (recon → inventory → evidence → reports) |
| Conditional for | Supervised small recon pilot on an authorized real target |
| NOT ready for | Autonomous hunting, model-driven payload testing |
| LLM agents running | **0** — briefs/guides are documents, not processes |
| Skills | **18**, all in `.claude/skills/` (8 recon guides + 10 hunting skills: 5 auth + SSRF + IDOR + XSS + SQLi + CSRF). OpenCode and Claude Code load them in sessions inside this repo; the engine loads none. |
| CSRF workflow | `hunt-csrf` + offline per-origin action × context × case ledger (`recon csrf sync/plan/record/status/verify`): fieldless/GET/GraphQL/realtime actions, 15 case families, facet-scoped reopening, browser-initiator record rules. Owned two-origin Chromium lab in the test suite. Not an exploit runner. |
| SSRF workflow | `hunt-ssrf` + 29-case offline ledger/correlation (`recon ssrf`) with `ssrf.depth_grants` (dns/internal/cloud/credential/protocol/execution or all) unlocking deep branches and `chain_next` ranking proven edges. Live execution remains browser/Burp-only; owned lab is the default without grants. Not an autonomous exploit runner. |
| Burp MCP | Connected in OpenCode at loopback `127.0.0.1:9876/mcp`; 27 tools discovered, shared across tool-capable models. Native Claude Code entry awaits project approval. Not a recon-enforced executor. |
| Dedicated visible browser | Profile/launcher prepared inside BugVault for Burp web proxy `127.0.0.1:8080`. Not launched or connected to browser tools; HTTPS CA/capture verification pending. Personal profile untouched. |
| Model routing | Policy only (`docs/model-routing.md`); no adapter, no gateway |
| Claude Max access | Native Claude Code is signed in to Max. Operator-requested `opencode-with-claude@1.11.2` + Meridian 1.79.0 works in OpenCode 2.2.6 through a loopback proxy; unofficial, with provider-policy risks (see below). |
| Campaigns configured | 0 (no `scope.json` exists yet) |
| Git state | Uncommitted working tree; nothing pushed |

## 3. Repository map

```
bugvault/
├── Handover.md               ← you are here
├── README.md                 project overview, status checklist
├── AGENTS.md                 shared scope, evidence and MCP guidance for all models
├── CLAUDE.md                 imports AGENTS.md for native Claude Code
├── opencode.json             project-wide Burp MCP + approval rules (no model override)
├── .mcp.json                 native Claude Code Burp MCP entry (project approval required)
├── LICENSE                   MIT
├── requirements.txt          pyarrow, requests (playwright optional, in .venv)
│
├── .claude/skills/           ★ THE ONLY SKILLS FOLDER (18; hidden dot-folder):
│                             8 recon phase guides + 10 hunting skills
│                             (hunt-auth-bypass, hunt-ato, hunt-mfa-bypass,
│                             hunt-oauth, hunt-saml, hunt-ssrf, hunt-idor,
│                             hunt-xss, hunt-sqli, hunt-csrf) — see §4 "Prompts & skills"
│
├── plans/                    ── THE FOUR DESIGN DOCUMENTS (platform not yet built)
│   ├── plan1.md              terminal draft: model routing, executor/observer core
│   ├── plan2.md              original vision: model council, WAF evolution, vuln modules
│   ├── plan3.md              full-coverage plan: 31 bug modules + 6 executor primitives
│   └── plan4.md              ★ master operating plan: recon levels L0–L4, phases P0–P6,
│                             validation gates, vault design, model routing §8
│
├── docs/
│   ├── model-routing.md      ★ model routing POLICY (DeepSeek V4.1 Flash primary)
│   ├── pentagi-analysis.md   lessons from PentAGI (per-agent model slots, failover)
│   ├── rea-analysis.md       REA reverse-engineering tool: analysis + integration plan
│   ├── h1-report-standard.md report template grounded in the report corpus
│   └── kb-expansion-pipeline.md  planned knowledge-base growth pipeline
│
├── recon/                    ── THE RUNNABLE ENGINE (see §4 below)
│   ├── README.md             ★ authoritative recon docs: safety model, dedup, limits
│   └── prompts/              agent brief templates (hunter/validator/reporter)
│
├── scripts/                  data pipeline (one-time / repeatable imports)
│   ├── download_dataset.py   fetch official H1 disclosed-reports parquet
│   ├── analyze_corpus.py     corpus stats (report length, bounty by class)
│   ├── build_dossiers.py     generate the 85 study-dossier notes
│   └── import_report_index.py  multi-source report-index importer (pinned snapshots,
│                             checksums, provenance, quarantine; heavily tested)
│
├── tools/burp/               optional stdio bridge + checksum-pinned JAR (binary gitignored)
├── tools/browser/            dedicated visible-profile launcher (state in .recon/browser/)
│
├── tests/                    363 tests, all offline or owned-loopback
│   ├── test_recon.py             core engine (scope, extract, pipeline, HAR, scoring)
│   ├── test_recon_boundaries.py  scope/budget/header/egress enforcement
│   ├── test_recon_ingest.py      offline scanner imports + catalog
│   ├── test_recon_findings.py    finding lifecycle, exploit lookup, briefs
│   ├── test_recon_review.py      review regressions, pinned egress, recovery, planning
│   ├── test_recon_factcheck.py   response-backed predicates
│   ├── test_recon_runtime.py     headless-browser SPA harvest (skips w/o playwright)
│   ├── test_recon_write.py       granted HTTP methods and request-payload evidence
│   ├── test_recon_takeover.py    provider signals and takeover-context regressions
│   ├── test_recon_skills.py      one skills folder, skill format/policy/licence, coverage→skill trigger
│   ├── test_recon_ssrf.py        40 SSRF tests: contexts, stale ledger, depth grants, chain edges, artifact/callback boundaries, bounded fetcher lab
│   ├── test_recon_csrf.py        31 CSRF ledger tests: inventory, readiness, record rules, facet reopening, effort, CLI/report, import metadata privacy
│   ├── test_recon_csrf_browser.py  owned two-origin Chromium lab (skips without Playwright)
│   ├── test_recon_chain.py       12 chain-todolist tests: templates, proven/ready/failed lineage, custom-chain validation, offline CLI
│   ├── test_recon_send.py        `recon send` executor + cross-process rate pacing
│   ├── test_burp_config.py       shared MCP endpoint/permissions; no live Burp required
│   ├── test_browser_profile.py   private profile/proxy policies; never opens a real browser
│   ├── test_import_report_index.py  importer regression suite
│   └── fixtures/recon/           offline scanner-output + HAR fixtures
│
├── vault/                    ── THE OBSIDIAN KNOWLEDGE BASE (open in Obsidian)
│   ├── README.md             vault index
│   ├── 35-Report-Studies/    85 dossier notes + _MOC.md (lessons per report)
│   ├── 10-Campaigns/         one folder per engagement (gitignored; holds scope.json)
│   ├── 90-Meta/              source provenance for the imported indexes
│   └── _data/                reports.csv (original 10,094), reports-merged.csv
│                             (combined 15,443), import manifest, quarantine
│
└── h1_train.parquet          cached dataset (gitignored)
```

## 4. The recon engine, file by file

Order roughly follows the data flow: **config → network → discovery → storage →
analysis → output**.

### Configuration & enforcement (the safety core)

| File | Purpose |
|---|---|
| `campaign.py` | Loads `scope.json`: scope rules (host/CIDR/URL/path/port), policy (mode passive/active/loud, rate limits, request budgets, IP allow/deny ranges). `Scope.check()` is called on **every** request and redirect hop. Discoveries never widen scope. |
| `net.py` | The only two network clients. `ScopedClient` (target; methods granted by `policy.allowed_methods`, default GET/HEAD, write methods an explicit grant; scope-checked per hop; write requests never auto-follow redirects; request bodies hashed) and `PassiveClient` (intel sources only, refuses in-scope hosts, never receives target headers). Shared per-instance budget + persistent campaign attempt counter. |
| `egress.py` | DNS-validated, pinned connections for built-in HTTP: rejects mixed public/private answer sets, connects to validated numeric sockaddr, checks the connected peer, keeps TLS SNI = original hostname. **Not** an OS-wide sandbox — see limits in `recon/README.md`. |

### Discovery (deterministic handlers)

| File | Purpose |
|---|---|
| `pipeline.py` | `Recon` class: the event-driven job queue. New asset → dependent jobs (domain→crtsh/wayback, host→probe, service→wellknown/jsharvest, js→jsparse, map→mapparse). Resumable; policy-blocked jobs skip with a reason and re-queue when mode allows. |
| `sources.py` | Passive jobs: crt.sh certificate transparency, Wayback CDX archive. |
| `active.py` | Active jobs: probe (DNS/CNAME/fingerprint/takeover), wellknown (robots/sitemap/security.txt/OIDC + soft-404 calibration), jsharvest (bounded same-origin HTML BFS from exact entry URLs), jsparse, mapparse. |
| `extract.py` | Pure parsing (no I/O): URL/endpoint normalization, ID-shaped path grouping, JS endpoint/route/permission/secret/GraphQL/chunk/sourcemap extraction. |
| `fingerprint.py` | Tech-stack signatures → tags → tool packs; SPA and subdomain-takeover signals. |
| `runtime.py` | Opt-in headless-browser SPA harvest (`runtime.enabled=true`): API calls answered with mocks, all real HTTP through the scoped client, WebSockets intercepted. |
| `har.py` | Offline HAR import (your own logged-in browsing): stores endpoint/method/param names/ID-like values + account/role/tenant/workflow labels, plus value-free CSRF metadata (`csrfmeta.py`). Never stores cookie or header values, or bodies. |
| `ingest.py` | Offline scanner-artifact import: BBOT, subfinder, httpx, Katana, ScopeSentry — surface records only; findings/vulnerability records are counted unsupported, never promoted. |

### Storage

| File | Purpose |
|---|---|
| `store.py` | SQLite operational store: assets, facts, observations, coverage, jobs, requests (+ bodies on disk by SHA-256), endpoint operations/variants, source imports + provenance, connection events, response captures, per-host pacing slots (`host_pacing`) that make `max_rps` hold across separate processes. |

### Analysis & output

| File | Purpose |
|---|---|
| `score.py` | Investigation-priority heuristics (source/auth/version/param signals) + bug-class applicability. Not a testedness proof. |
| `report.py` | Writes `recon.md`, `coverage.md`, `intel.md` (+ `findings.md`): inventory, context-specific parameter tables, comparison groups, provenance, policy-skipped work. `coverage.md` has a `skill` column naming the skill to load per row. |
| `skillmap.py` | Skills folder location (`.claude/skills`) and coverage class → skill map: `ato` → `hunt-auth-bypass`, `hunt-ato`; `mfa-bypass` → `hunt-mfa-bypass`; `oauth` → `hunt-oauth`; `saml` → `hunt-saml`; `ssrf` → `hunt-ssrf`; `idor-bola` → `hunt-idor`; `xss`/`html-injection` → `hunt-xss`; `sqli`/`ssti` → `hunt-sqli`; `csrf` → `hunt-csrf`. |
| `csrf.py` / `csrfmeta.py` | CSRF action ledger: per-origin actions (fieldless, GET, GraphQL operations, realtime) × contexts × 15 case families with variants; facet-scoped reopening; record rules for browser-initiated attempts; hash-bound artifacts; `recon csrf sync/plan/record/status/verify`. `csrfmeta.py` derives value-free capture metadata for HAR/Burp imports. Offline only. |
| `ssrf.py` | Offline 29-case SSRF matrix, exact URL/method/account/role/tenant/workflow/field ledger, hash-bound artifacts and normalized callback correlation. No HTTP/DNS/browser/cloud execution, native-fact import or automatic finding promotion. |
| `findings.py` | Finding lifecycle: lead → confirmed (replay + distinct negative control required) → impact-proven → reported → outcome. Chain links (11 relations incl. lineage `spawns`/`derived-from`/`proves`) + automatic chain hints. Outcome log for future ranking. |
| `chain.py` | Cross-class chain todolist (ARTEX shared-todolist idea, deterministic): built-in templates from the hint table plus validated custom chains; steps resolve `proven` (finding at confirmed+), `ready`, `lead-open`, `failed`/`blocked` from the findings store; `recon chain status`; surfaced in `findings.md`. Offline only; orders the hunt, executes nothing. |
| `vulnintel.py` | Exploit lookup: fingerprinted versions → SearchSploit/Sploitus/CISA KEV → ranked leads with precondition checklists. Sends no target request. |
| `reliability.py` | Bounded intel-provider fallback: ≤2 tries/provider, write-ahead attempts, 1h success cache, 30s failure cooldown, 3-strikes suppression. Policy/budget errors stop the chain. |
| `recall.py` | Offline lexical recall over ≤5,000 records with row/import references and snapshot hashes. No embeddings, no model calls. |
| `factcheck.py` | Response-backed predicates: `status_is`, `header_present`, `header_equals`, `body_contains_raw` — checked against a specific stored response; supported/contradicted/inconclusive/stale. `fact context` re-verifies and refuses unsupported exports. |
| `planning.py` | Offline planning boundary: export ≤100 asset snapshots; validate external JSON proposals (≤20 known-handler intents, scope+hash checked); `--apply` enqueues only, never executes. No model calls. |
| `brief.py` | Renders the 3 agent briefs with a bounded pre-authorization block generated from `scope.json`. Documents, not agents. |
| `catalog.py` | Executable capability inventory: phases, skills, tools, integration status, actual agent counts. `catalog --json`. |
| `cli.py` / `__main__.py` | All commands (see §5), including `send`: one request through `ScopedClient` (scope, method grant, mode, budgets, pinned egress, cross-process rate), stored as evidence with a `request_id`. It is the executor the hunting skills use. |

### Prompts & skills (documents, not running agents)

Prompts are in `recon/prompts/`. **Every skill is in `.claude/skills/<id>/SKILL.md`**
at the repository root, the only skills folder (tests fail on a `SKILL.md` anywhere
else). OpenCode and Claude Code discover it in sessions opened inside this repository
and load a skill when a task matches its description; `@<skill-id>` forces one. The
recon engine itself loads none. Verified: a fresh OpenCode session, given a login `ato`
row and asked to load the applicable skill without being told its name, chose and
loaded `hunt-auth-bypass`.

| Path | Purpose |
|---|---|
| `recon/prompts/hunter.md` | Hunting loop: pick untested rows, load the row's skill, send requests with `recon send`, two accounts for auth checks, three-attempt rule, noise list, chain-hint awareness, lookup/recall usage. |
| `recon/prompts/validator.md` | Triage gate: scope → precondition → deterministic replay → negative control → privilege-vs-impact → root-cause duplicate check → impact. Distinguishes positive controls from negative assertions. |
| `recon/prompts/reporter.md` | Report structure for confirmed+ findings only; never describe unperformed steps. |
| `.claude/skills/scope-policy/SKILL.md` | Reviewing authorization, scope, mode, budgets before any run. |
| `.claude/skills/passive-discovery/SKILL.md` | L0 passive collection + subfinder/BBOT imports. |
| `.claude/skills/service-mapping/SKILL.md` | L1 probing + httpx/ScopeSentry imports (reported ≠ measured). |
| `.claude/skills/static-api-mapping/SKILL.md` | L2 HTML/JS/map extraction + Katana import; bounded BFS. |
| `.claude/skills/apk-static-mapping/SKILL.md` | Mobile surface from authorized APKs via external REA/JADX static analysis; untrusted leads only. |
| `.claude/skills/synthetic-ui-mapping/SKILL.md` | L3 opt-in mocked-browser exploration (synthetic ≠ backend access). |
| `.claude/skills/captured-auth-mapping/SKILL.md` | L4 HAR imports with account/role/tenant/workflow labels. |
| `.claude/skills/inventory-handoff/SKILL.md` | Reports, recall, fact checks, planning boundary, honest uncertainty. |
| `.claude/skills/hunt-auth-bypass/SKILL.md` | **Login bypass** (class `ato`, primary): missing auth, client-trusted headers/cookies, JWT alg/key confusion, reset-token leaks, magic-link replay, session fixation, internal self-signup, XML-RPC multicall. |
| `.claude/skills/hunt-ato/SKILL.md` | Account-takeover chain target (class `ato`, second): reset tokens and reset-link host poisoning, email-change CSRF, missing re-authentication, OAuth account linking. |
| `.claude/skills/hunt-mfa-bypass/SKILL.md` | MFA/2FA (class `mfa-bypass`): enforcement gaps, step skip, OTP reuse, bounded (≤25 attempts) rate-limit proof, recovery codes, remember-device trust. |
| `.claude/skills/hunt-oauth/SKILL.md` | OAuth/OIDC (class `oauth`): redirect_uri, state, nonce, PKCE, token audience, browser-vs-server URL parsing. |
| `.claude/skills/hunt-saml/SKILL.md` | SAML/SSO (class `saml`): signature wrapping and stripping, comment injection, audience, replay, XXE. |
| `.claude/skills/hunt-idor/SKILL.md` | IDOR/BOLA/BFLA (class `idor-bola`): staged substitution ladder from marker-proven A→V swaps through request-shape variants, vertical/cross-tenant checks, write proofs on disposable objects and chain targets; comparison groups come from HAR `idor_candidates`. |
| `.claude/skills/hunt-ssrf/SKILL.md` | SSRF: surfaces/triggers, controlled causality, parser/address/redirect/DNS/rendering matrix, scoped internal/cloud branches, owned-lab protocol/execution chains and reportability. |

The five auth `hunt-*` skills are adapted from mind-hunt (MIT, © 2026 MindflareX; the notice
and source SHA-256 are in each folder's `LICENSE.txt` and frontmatter). Removed from the
originals: full-keyspace OTP brute force, proxy/IP rotation, breach-corpus password
spraying, own HTTP clients (curl/aiohttp/ffuf), real-user identities and references to
skills outside the folder; `tests/test_recon_skills.py` fails if any of them return.
The skills now describe operator-run Repeater synchronized groups for OTP races and
Collaborator callbacks (MCP generation/polling tools available). The single shared
workflow, evidence requirements and fallback implementation plan live in
`.claude/skills/scope-policy/references/burp-workflow.md`. Recon still has no native
burst executor, Burp scope/budget adapter or external-fact importer. The current MCP
creates Repeater/Intruder tabs but cannot run a synchronized group or an Intruder
attack. `jku`/`x5u` key-trust proof also needs controlled JWKS/certificate hosting;
a callback alone is not takeover. Park work when permission/tools/proof are missing.

`hunt-ssrf` is an original workflow, with pinned references to the supplied HackTricks
fork and BugBountySkills SSRF knowledge base in its `references/sources.md`. HackTricks
is a 2023 CC BY-NC 4.0 snapshot; no prose/payload tables were imported. The second
source contains mixed XSS concepts, placeholder examples and inconsistent bounty
claims, not accepted as verified evidence. Current vendor metadata prerequisites
were separately checked. The case ledger retains stale history and uncertainty;
external request counts are operator assertions, not native budget enforcement.
Three attempts are per-case effort, not complete endpoint-wide SSRF coverage.

The three text-only skill comparisons and static review viewer are at
`.recon/skill-evals/hunt-ssrf/iteration-1/review.html`. Narrow output checks passed
12/12 with the skill versus 6/12 without; both respected the supplied browser/scope
constraints. Integration-specific checks favor the skill by design. These are not
live exploit tests or statistically meaningful detection benchmarks, and no timing/
token metrics were supplied.

## 5. Everyday commands

```bash
python3 -m recon catalog --json            # what actually exists
python3 -m recon init demo --seed https://app.example.com --mode passive
#   → edit vault/10-Campaigns/demo/scope.json from WRITTEN program rules
python3 -m recon check demo https://app.example.com/api/x
python3 -m recon run demo --max-jobs 100   # resumable
python3 -m recon import demo out.jsonl --format httpx      # offline import
python3 -m recon import-har demo alice.har --account alice --role member --tenant a
python3 -m recon lookup demo               # versions → exploit leads (no target traffic)
python3 -m recon responses demo            # stored response IDs
python3 -m recon send demo https://app.example.com/api/me --header "X-Authenticated: true"
#   → one scoped request, stored as evidence; prints request_id (skills' executor)
python3 -m recon send demo https://app.example.com/api/login --method POST --json '{}'
#   → write methods need policy.allowed_methods in scope.json
python3 -m recon fact check demo --response 12 --predicate '{"type":"status_is","expected":200}'
python3 -m recon fact context demo 1 2 3   # re-verified context export
python3 -m recon recall demo "tenant export"
python3 -m recon plan demo                 # planning context; no model called
python3 -m recon ssrf plan demo --asset-id 12 --context context.json   # offline case matrix
python3 -m recon ssrf status demo --asset-id 12 --context context.json # latest outcomes/integrity
python3 -m recon ssrf correlate demo --asset-id 12 --bundle bundle.json # normalized external evidence
python3 -m recon chain status demo              # cross-class todolist: ready/waiting/proven steps
python3 -m recon chain add demo --file chain.json  # record a validated custom chain
python3 -m recon finding add demo --title "..." --class idor-bola --url ...
python3 -m recon finding move demo 3 confirmed --replay r.txt --control c.txt
python3 -m recon brief demo                # render hunter/validator/reporter briefs
python3 -m recon status demo && python3 -m recon report demo

# Tests (257; the .venv has playwright so the browser test runs too):
.venv/bin/python -m unittest discover -s tests -v
```

New authorized active campaigns can grant additional methods at initialization:

```bash
python3 -m recon init demo-auth --seed https://app.example.com --mode active \
  --allow-method POST --allow-method PUT --allow-method PATCH \
  --allow-method OPTIONS --allow-method DELETE
```

Defaults stay GET/HEAD. Existing configs are never overwritten; set their
`policy.allowed_methods` explicitly to the permitted subset of
`["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"]`, using active/loud mode.

### Shared Burp access and data across models

`opencode mcp list` in this repository reports `burp connected`. The registration is
project-wide, not under a provider or model, so every tool-capable OpenCode model can
use the same history/Organizer/scanner data and local campaign artifacts. Independent
sessions do not share hidden conversation memory; preserve evidence under the campaign.
`claude mcp list` sees the same HTTP endpoint but reports pending project approval:
run `claude` here and approve the entry once. Do not disable Burp's own approvals.

Verified on 2026-11-12: MCP initialization (`burp-suite` 1.1.2), 27 tools and one local
URL-encoding call, with no target traffic or history dump. This is not a live test of
every model/provider or callback service. Keep raw secrets out of unrelated provider
contexts. Active Burp actions are approval-gated and not included in generated briefs;
scope/rate/budget checks in recon do not constrain Burp traffic. The proxy JAR is
copied byte-for-byte into `tools/burp/mcp-proxy.jar` (checksum in that folder's README,
binary gitignored); direct HTTP needs no JAR. All runtime paths stay in BugVault.

### Dedicated visible browser (prepared, connection pending)

`python3 tools/browser/launch.py --prepare` created the private agent-only profile at
`.recon/browser/profile/` and checked that Burp's loopback web proxy listens on port
8080. To open it, the operator runs `python3 tools/browser/launch.py`. No personal
profile or cookies are reused. The fixed proxy has no DIRECT fallback; QUIC is
disabled, loopback web requests are included, and no TLS/sandbox bypass flags or
remote-debugging ports are used. This is not OS-wide egress isolation.

This conversation has no browser-control tools connected, so no Chrome window was
launched and no login, signup, mailbox reading or target navigation was performed.
The operator must connect Claude in Chrome in the dedicated profile, approve any
necessary Burp CA trust, and verify HTTP/HTTPS capture before live use. FoxyProxy
can be installed there but must not conflict with the fixed startup proxy or bypass
it. Use only test mailboxes/accounts and verify full email-link destinations. The
workflow is `.claude/skills/scope-policy/references/browser-workflow.md`.

### Imported takeover references

`python3 scripts/import_report_index.py --out vault --source takeover` maintains
165 source-attributed discovery pointers in `vault/_data/reports-merged.csv`.
All 165 IDs were already present, so the combined index remains **15,443 IDs**.
The original dataset and 85 dossiers remain unchanged. `bbtakeover_*` labels are
unverified source claims, not reproduced findings or validated severity statistics.
Raw data is cached at revision `e0414b47a7de0f5588adb9404de7c6975614f2c0`;
checksums and caveats are linked from
`vault/90-Meta/sources/bugbountyskills-subdomain-takeover.md`.

### Claude subscription access (verified locally)

Run `claude` from the repository directory to use the existing Max subscription
without an API key. `claude auth status` confirms the login; on macOS, absence of
`~/.claude/.credentials.json` does not establish that the CLI is signed out.
No credential contents were pasted, printed, or manually copied for this setup.

The attempted `@life-ai-tools/opencode-claude@0.7.0` registration failed OpenCode
2.2.6's plugin contract (missing a default plugin definition with `setup`/`effect`).
Its entry was removed from `~/.config/opencode/opencode.jsonc`; the Ollama settings
were preserved and the npm package remains installed but inactive. Restarting or
signing in again does not fix that incompatibility.

The later operator-requested [ianjwhite99/opencode-with-claude](https://github.com/ianjwhite99/opencode-with-claude)
integration **does work technically** with this OpenCode V2 installation:

- Exact package `opencode-with-claude@1.11.2`, depending on Meridian `1.79.0`;
  npm manifest `gitHead` matches upstream commit
  `49ea7693598b1a349d00010bc7a1191bc3d6c083`.
- Installed into `~/.config/opencode/node_modules/` with lifecycle scripts disabled;
  version and registry integrity are retained in that directory's package lock.
- Global config `~/.config/opencode/opencode.jsonc` loads the installed `dist`
  directory and points `providers.anthropic.settings.baseURL` at
  `http://127.0.0.1:3456/v1`. `apiKey: "dummy"` is a local placeholder, not an
  Anthropic API key. The plugin replaces the endpoint with its actual proxy port.
- The proxy uses existing Claude authentication, reports Max and passthrough mode,
  and was verified listening only on `127.0.0.1:3456`. No extra profiles or account
  rotation were configured. Ollama and the current/default model were not changed.
- A fresh, archived OpenCode session in an empty temporary directory requested
  `anthropic/claude-sonnet-5-5` and returned exactly `CLAUDE_CONNECTION_OK`.
  No tool calls or BugVault files were sent in that smoke test. This verifies one
  text round trip, not every tool or long-session workflow.

To use it, open `opencode` in this repository, then use `/models` to select Claude
Sonnet 5.5. Configuration hot-reloads; `/reload` is available if needed.

This is an **unofficial subscription bridge**, not an endorsed API integration.
Its source includes system-prompt fingerprint rewriting and it is trusted with the
existing Claude login. Anthropic's [authentication policy](https://code.claude.com/docs/en/legal-and-compliance#authentication-and-credential-use)
restricts third-party subscription-token routing; a successful local test is not
provider approval or a guarantee against account restrictions. Do not expose the
proxy beyond loopback or send campaign data without the required approval.

This does not implement BugVault's model gateway, automatic role routing, or
independent validation. Remove this plugin entry and the added Anthropic settings
to disable it; pre-change config/package files are backed up at
`/private/var/folders/99/gjl2y2ls4jz4xwbbybypc5r00000gn/T/opencode/opencode-meridian-setup-0t319ucn/`.

## 6. The three safety rules that must never be regressed

1. **Scope is enforced in code, per request and per redirect hop** — never only in
   prompts, never widened by discoveries, exclusions win, URL userinfo rejected.
2. **Evidence gates check artifacts, not claims** — `confirmed` needs a replay AND
   a distinct negative control; fact checks verify exact predicates against stored
   responses; a marker match is never "XSS confirmed."
3. **Policy/budget failures stop the chain** — they are never a reason to fall
   back, retry via another path, or switch models (see `docs/model-routing.md` §4).

## 7. Where things are decided & documented

| Topic | Authoritative doc |
|---|---|
| Recon safety model, dedup, limits | `recon/README.md` |
| Model routing policy & audit contract | `docs/model-routing.md` |
| Full platform design (P0–P6, gates) | `plans/plan4.md` |
| PentAGI routing lessons | `docs/pentagi-analysis.md` |
| Report writing standard | `docs/h1-report-standard.md` |
| What code actually runs | `python3 -m recon catalog --json` |

## 8. Next milestones (priority order)

1. **Owned loopback demo end-to-end** — proves the chain without any real target.
2. First real authorized pilot — small scope, passive+active, human-reviewed.
3. Model gateway + audit trail (`docs/model-routing.md` §5–§7), fallback slot
   filled by operator.
4. Context-completeness gate for payload tasks (builds on `fact context`).
5. OS-level egress isolation — **before** any payload loop runs autonomously (the
   scoped write-method client itself now exists: `policy.allowed_methods` +
   `ScopedClient.request()`).
6. Hunt-phase bug modules (plan3's 31) driven by the coverage matrix. Skills exist
   for `ato`, `mfa-bypass`, `oauth` and `saml`; the burst executor (OTP races) and an
   out-of-band listener (`jku`/`x5u`/XXE) they would need are not built.

## 9. Conventions for anyone extending this

- Stdlib-only Python 3.9+ (playwright optional in `.venv`). Every new network
  path must go through `net.py` clients — no `requests`, no curl, no raw sockets.
- Every claim about capability must match `catalog` output; update it with code.
- New skills go only in `.claude/skills/<id>/SKILL.md` (a folder whose name equals the
  frontmatter `name`); map coverage classes in `recon/skillmap.py`, list the skill in
  `recon/catalog.py`, and send requests with `recon send`, never curl.
- Tests are offline or owned-loopback; no bounty targets, no model APIs, no
  paid calls. New behavior needs a regression test before it's "done."
- Campaign data (`vault/10-Campaigns/*`, `.recon/`) is gitignored and private —
  it contains target data and possibly secrets.
- Say "not implemented" when something isn't. This repo's credibility is the
  gap between what it claims and what it does — keep that gap at zero.
