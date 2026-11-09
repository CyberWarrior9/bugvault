# Recon: ARTEX-inspired, independently implemented

Runnable Python 3.9+ recon foundation, extending the existing BugVault engine. Deterministic collection and offline imports, not autonomous vulnerability exploitation. No ARTEX AGPL source was copied into this MIT implementation.

## Actual agents, skills and phases

| Component | BugVault implemented | ARTEX reference |
|---|---|---|
| LLM agents used by recon | **0** | 1 planner + configurable workers; default 3 workers = **4 ongoing instances**, plus a one-shot goals decomposer |
| Scheduling | **1 sequential deterministic scheduler**, **8 job handlers** | Event-driven LLM planner/frontier and concurrent workers |
| Recon skills | **7 repository capability guides** below; **0 automatically invoked LLM skills** | `api-recon` enabled for default workers; `bbot-recon`, `scopesentry`, browser support optional/configurable |
| External artifact adapters | **5 scanner formats + HAR** | BBOT events, ScopeSentry sync and live traffic extension |
| Model routing | Not implemented | Agent bindings/fallbacks configurable |

The seven guides are `recon/skills/<phase-id>/SKILL.md`. They document real handlers/commands and can be read by an operator or agent, but are not installed into an agent harness or automatically loaded by this engine. No claim of evaluated model behavior is made. Qwen/GLM/OpenAI review agents are **not running**; credentials, endpoints, model IDs and a separate bounded review adapter would be required.

| Phase / guide ID | Tools and handlers | Data produced |
|---|---|---|
| `scope-policy` | scope checks, mode and budget gates | Operator-controlled authorization; never widened by discoveries |
| `passive-discovery` (L0) | `crtsh`, `wayback`; offline subfinder/BBOT | Hostnames, historical URLs, archive references |
| `service-mapping` (L1) | `probe`, stdlib DNS/HTTP, optional `dig`; httpx/ScopeSentry imports | IP/name associations, origins, fingerprints; imported claims labelled separately |
| `static-api-mapping` (L2) | `wellknown`, `jsharvest`, `jsparse`, `mapparse`; Katana import | Endpoint families, methods, parameter names, JS/chunks/maps, frontend routes |
| `synthetic-ui-mapping` (L3) | `runtime`, optional Python Playwright + Chromium | Synthetic UI/client-attempted API surfaces, not backend access |
| `captured-auth-mapping` (L4) | Offline HAR import | Account × role × tenant × workflow observations |
| `inventory-handoff` | Local scoring/reporting | `recon.md`, `coverage.md`, `intel.md`; unvalidated leads |

These are capability phases, not seven always-running agents or a rigid completion barrier. New assets enqueue dependent jobs; imports/reporting are explicit commands. `max_jobs` limits queue work, not HTTP request count.

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
python3 -m recon status acme
python3 -m recon report acme
```

Imports and reports are **offline**. Imported assets may enqueue jobs, but only a subsequent explicit `run` executes them, under its scope/mode. A malformed-record import returns exit code 2 with counts and bounded redacted error locations. Invalid file envelopes/size fail before import registration. Never treat every file called JSON as a supported export; schemas are listed below.

### Findings, exploit lookup and agent briefs

```bash
python3 -m recon lookup acme                     # recorded versions -> searchsploit + Sploitus + CISA KEV -> leads
python3 -m recon finding add acme --title "IDOR on invoices" --class idor-bola --url https://app.acme.com/api/invoices/7
python3 -m recon finding move acme 3 confirmed --replay replay.txt --control control.txt
python3 -m recon finding move acme 3 impact-proven --impact impact.txt --severity high
python3 -m recon finding link acme 2 yields-token 3        # chains appear in findings.md
python3 -m recon finding move acme 3 reported --report report.md
python3 -m recon finding move acme 3 duplicate --note "dup of #2345678"
python3 -m recon brief acme                      # agents/hunter.md, validator.md, reporter.md
```

- **Stages** (`recon/findings.py`): `lead → confirmed → impact-proven → reported → accepted | duplicate | informative | n-a`, or `killed` with a reason. `confirmed` is refused without a replay artifact **and** a different negative-control artifact. Artifacts are copied to `.recon/evidence/` by SHA-256. The tool records them; judging them is the validator's job. Stage changes update the matching coverage row (`lead` → queued, `confirmed`, `killed` → refuted). Findings are only accepted for in-scope URLs.
- **Links and chains:** relations `yields-token`, `yields-id`, `yields-access`, `authenticates-to`, `escalates-via`, `pivots-to`, `enables`, `same-root-cause`. `findings.md` lists linked chains plus *chain hints*: unlinked findings on one host whose classes commonly combine (open redirect + OAuth, XSS + CSRF, IDOR + ATO, …).
- **Outcome log:** every transition is a `finding_events` row with class, severity and tech. This is the raw history for a later "what worked for me" ranking. No ranking is built from it yet.
- **Exploit lookup** (`recon/vulnintel.py`): sends **no target request**. Versions come from responses `run` already recorded (Server/X-Powered-By/X-Jenkins headers, CMS generator tags, Confluence/GitLab/Grafana markers, JS library banners) and from imported httpx `tech`. Searches: local `searchsploit` (if installed; product+version and product-only, so range titles like `< 3.5.0` are found), Sploitus (JSON POST of `"<product> <version>"` only; refused if the payload names an in-scope host), and the CISA KEV feed (cached 24 h in `.recon-cache/`). Exploits are kept only if the title names this version or a range containing it. CMS plugin/theme advisories are dropped. Priority: exploit for a KEV CVE +5, KEV product match +2, exact version +3 / range +2, remote/webapp +1, server-side +1, client-side library −4. Each lead stores a precondition checklist: version evidence, reachability, payload-free check, then a minimal proof.
- **Agent briefs** (`recon/brief.py`, templates in `recon/prompts/`): each prompt opens with a pre-authorization block generated from `scope.json`. It says agents act without asking permission or adding disclaimers, and lists in/out of scope, mode, rate limit, `rules` and `excluded_bug_classes`. It also says out-of-scope requests fail in the tooling and must not be worked around. Scope is still enforced in code.

### Complete tool inventory and integration status

`catalog` is the executable source of truth (`recon/catalog.py`); it checks PATH/package presence without executing tools or contacting services.

- **Native:** crt.sh, Wayback CDX, stdlib HTTP/DNS/HTML/JS/source-map extraction and fingerprint signatures.
- **Optional native:** `dig` for CNAME lookup; Python Playwright and installed Chromium for opted-in synthetic browsing.
- **Offline adapters only:** BBOT, subfinder, ProjectDiscovery httpx, Katana, ScopeSentry; HAR from browser DevTools/Burp/Caido.
- **Manual only, no executor/adapter:** Nmap and ffuf.
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
| HAR | `log.entries[].request` and response status/MIME; no replay and no raw bodies imported |

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

## Execution boundaries and remaining limits

- Explicit URL scope rules retain scheme/port/path; bare hostname/CIDR rules intentionally allow all ports. Exclusions win. URL userinfo is rejected. Discoveries never edit `scope.json`.
- Target HTTP is GET/HEAD only and checked per redirect. Cross-origin redirects drop custom headers; passive providers never receive target authorization headers.
- Target and passive HTTP share `policy.max_requests` (default 1000) and `max_seconds` (default 600) per Recon process/instance, counting attempted sends. Rate limits are per host. Socket timeouts are bounded by remaining time, but this is **not a hard wall-clock/process sandbox**; DNS and slow reads may overrun it. `dig` has its own timeout.
- Runtime is disabled unless `runtime.enabled=true`. All real browser HTTP reads use the shared scoped client; no `route.continue_()` target bypass. Unsupported WebSocket interception fails closed. API requests are mocked unless live GET is explicitly enabled. Browser cookies/storage are synthetic rendering aids, not replayed credential sessions; use HAR for real authenticated mapping.
- **DNS-pinned/per-connection IP enforcement is not implemented.** A scoped hostname resolving to a private/rebound address is not reliably isolated; configured proxies also control connection routing. Use a controlled lab or independently enforced program egress controls. Do not call this production-safe isolation.
- GET can change state on poorly designed applications; URL scope and method restrictions do not guarantee no side effects. Review excluded paths. No automatic credential login, exploit/fuzzer execution, port scan, or account mutation is included.
- Static extraction is heuristic: full dynamically constructed webpack/Vite manifests, arbitrary API base URLs and parameter semantics are not reconstructed. Collection is bounded, not complete.
- Active service collectors are origin-root-oriented; narrow path-only grants may skip jobs rather than crawl the granted entry path. Offline URL/HAR intake still applies full path exclusions. Do not widen authorization to make a collector work.
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

Tests use offline fixtures and owned loopback servers, not bounty targets or model APIs. The capability guides have structural/code-reference tests, **not** agent behavioral benchmarks.

Small reserved-domain fixtures live in `tests/fixtures/recon/`. To exercise every adapter offline, initialize a disposable campaign with no seeds and `in_scope: ["example.com", "*.example.com"]`, import the five scanner files, then import `alice.har` and `bob.har` with different account labels. Importing Alice twice with the same labels must retain two total HAR samples, not three. Do **not** run the queued fixture assets against example.com; they are synthetic, not authorization.

Architectural reference: [ARTEX at 9bf5d816](https://github.com/BaaRai/ARTEX/tree/9bf5d816aeb361d79de874fcdbeeb0de31bd83f2), especially planner/worker separation, api-recon, bbot-recon, asset/exploration graphs and traffic capture. ARTEX is AGPL-3.0; this code uses independently implemented ideas, not copied scripts or prompts.
