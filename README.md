
# BugVault — Autonomous Bug-Hunting Knowledge Base & Platform Plans

An authorized bug-bounty hunting knowledge system: a git-versioned Obsidian vault
(the AI context layer), data-grounded report standards, multi-agent platform designs,
and reproducible analysis pipelines built on HackerOne's official disclosed-reports dataset.

> **Scope:** authorized testing only — bug bounty programs, owned lab environments,
> and contracted engagements. All techniques and doctrine in this repo are for
> building tooling that operates within written scope.

---

## What's in here

```
├── plans/                    # The four design documents
│   ├── plan1.md              # Terminal draft — model routing, executor/observer/classifier core
│   ├── plan2.md              # Original vision — model council, WAF evolution, vuln modules
│   ├── plan3.md              # Full-coverage plan — 31 modules + 6 executor primitives + web3 track
│   └── plan4.md              # Master operating plan — recon levels, tech-stack packs,
│                             #   Obsidian vault design, model routing, validation gates
├── vault/                    # The Obsidian vault (open it directly in Obsidian)
│   ├── 35-Report-Studies/    # 85 dossier notes of top-voted, bounty-paid H1 reports
│   │   └── _MOC.md           #   index + exemplar lessons + report standard
│   ├── _data/reports.csv     # Original H1 dataset index: 10,094 reports (preserved)
│   ├── _data/reports-merged.csv # Combined discovery index, deduplicated by report ID
│   └── 90-Meta/sources/      # Source provenance, coverage, and interpretation notes
├── recon/                    # Recon engine: python3 -m recon (see recon/README.md)
├── scripts/                  # Reproducible pipeline (see below)
├── docs/
│   ├── h1-report-standard.md     # What paid reports actually contain (data-grounded)
│   ├── kb-expansion-pipeline.md  # How new knowledge (X posts, writeups) enters the vault
│   └── pentagi-analysis.md       # Deep-dive on the PentAGI platform (architecture + gaps)
└── README.md
```

## Quickstart

```bash
pip3 install -r requirements.txt

# 1. Download HackerOne's official disclosed-reports dataset (parquet, ~15MB)
python3 scripts/download_dataset.py

# 2. Analyze the corpus (format/quality/quantity of paid reports)
python3 scripts/analyze_corpus.py

# 3. Build the vault dossiers from the dataset
python3 scripts/build_dossiers.py --parquet h1_train.parquet --out vault

# 4. Merge the pinned reddelexc/hackerone-reports metadata index
#    Preserves the original index and dossiers; reuses its cached snapshot on reruns.
python3 scripts/import_report_index.py --out vault

# 5. Add the pinned codebygk JSON index (retains the reddelexc import)
python3 scripts/import_report_index.py --out vault --source codebygk

# 6. Enrich existing IDs with the pinned BugBountySkills takeover index
python3 scripts/import_report_index.py --out vault --source takeover

# Validate an import without writing, or run importer regression tests
python3 scripts/import_report_index.py --out vault --dry-run
python3 -m unittest discover -s tests -v
```

## The vault

Open `vault/` as an Obsidian vault. It is plain markdown, git-versioned, and designed
to be read/written directly by AI agents (no API needed — filesystem access only).

- **85 report dossiers** (`rs-<h1_id>.md`): attack narrative, why-it-paid, technique
  links, evidence flags, full report text — one per top-voted bounty-paid report,
  stratified across 14 vulnerability classes.
- **Frontmatter is the query layer.** Example Dataview query for a class playbook:

```dataview
TABLE team, votes, primitives
FROM "35-Report-Studies"
WHERE class = this.file.name
SORT votes DESC
```

- The `[[class]]` links in dossiers point to future `30-Bug-Classes/` playbook notes
  (see `vault/README.md` for the planned structure).
- **Expanded discovery index:** `vault/_data/reports-merged.csv` merges the original
  dataset with commit-pinned [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports)
  and [codebygk/hackerone-bug-bounty-reports](https://github.com/codebygk/hackerone-bug-bounty-reports)
  snapshots. Existing fields take precedence; external metadata and provenance are
  stored separately. Imports are `source-indexed`, **not independently reproduced**.
  Historical `codebygk_severity` values are source claims, not current severity decisions.
  See [all source coverage and caveats](vault/90-Meta/sources/_MOC.md).
  Rerunning either source rebuilds the combined index from all registered snapshots.
  No report bodies or private reports are fetched by this importer.
- **Takeover discovery pointers:** 165 existing IDs are additionally attributed to
  the pinned BugBountySkills index (`bbtakeover_*` columns). This adds metadata, not
  165 new reports or validated case studies. Its category/severity labels are
  unverified source claims; missing bounties stay unknown. See the
  [source note](vault/90-Meta/sources/bugbountyskills-subdomain-takeover.md).

## Key findings baked into the docs

- 94% of top bounty reports have an explicit **Impact section** (median 26 words)
- Report length sweet spot: **3k–10k chars** (66% bounty rate); under 300 chars only
  works with directly demonstrated impact
- Bounty rate by class: memory corruption 84% · privilege escalation 46% ·
  HTTP smuggling 44% · XSS-DOM 46% · CSRF 33%
- The report template for automated report-writing agents (docs/h1-report-standard.md)

## Recon capability inventory

ARTEX-inspired recon includes a phase/tool catalog, five offline scanner-output
adapters plus context-labelled HAR imports, method-specific operations and source
provenance. Run `python3 -m recon catalog`; see [`recon/README.md`](recon/README.md)
for the skills, deduplication rules, actual agent counts (**zero LLM agents**) and
remaining execution-isolation limits.

**Skills:** all 26 BugVault skills are in one folder, `.claude/skills/` (8 recon phase
guides + 18 hunting skills: the authentication set `hunt-auth-bypass`, `hunt-ato`,
`hunt-mfa-bypass`, `hunt-oauth`, `hunt-saml`, plus `hunt-ssrf`, `hunt-idor`, `hunt-xss`,
`hunt-sqli`, `hunt-csrf`, `hunt-ssti`, `hunt-access-control`, `hunt-file-upload`,
`hunt-js-bundle`, `hunt-business-logic`, `hunt-race-conditions`, `hunt-takeover` and
`hunt-cloud-misconfig`). OpenCode and Claude Code load it
automatically in sessions inside this repository; `coverage.md` names the skill to use
for each row. `python3 -m recon send` is the native scoped executor, but this operator's
live tests must originate in the dedicated browser through Burp unless separately approved.

**Cloud misconfiguration (partial):** `hunt-cloud-misconfig` and
`python3 -m recon cloud import|generate|sync|plan|show|record|status|verify` support
offline cloud references, scoped hostname proposals, ranking and operator evidence with integrity checks.
No provider probes, credential use, owned cloud lab, Prowler adapter or real
impact channel was added. The R1–R8 implementation status and open gates are
in [`plans/cloud-misconfiguration.md`](plans/cloud-misconfiguration.md).

**SSRF workflow:** [`hunt-ssrf`](.claude/skills/hunt-ssrf/SKILL.md) covers surface/trigger
selection, controlled attribution/readback, parser/redirect/DNS comparisons, rendering,
internal/cloud/credential/protocol branches and execution chains. Deep branches follow
`ssrf.depth_grants` in `scope.json` (dns/internal/cloud/credential/protocol/execution
or `["all"]`), copied from the program's written rules — credential read/use and
host/port/protocol swapping against internal services run at full depth under their
grants, with every destination still scope-checked. The 29-case offline ledger
(`recon ssrf plan|record|status|correlate`) preserves exact contexts, hashed
artifacts and uncertainty, and ranks proven chain edges (`chain_next`). Owned lab
remains the default where no grant exists. Both supplied references are pinned and
quality-reviewed in the skill's `references/sources.md`.

**Business invariants and race:** `python3 -m recon logic --help` and
`python3 -m recon race --help` expose offline declarations, anomaly leads, exact
case evidence and bounded operator-attested run imports over one model. They do
not send requests, run synchronized gates or create findings. One deterministic
owned-loopback vulnerable/fixed/serial/replay fixture is tested; the full
18-scenario laboratory plan and an agent-driven protocol/budget broker are not
complete. See [`recon/README.md`](recon/README.md) for exact limits and gates.

**Shared Burp MCP:** `opencode.json` exposes the loopback service on port 9876 to
every tool-capable model selected in this project; `.mcp.json` supplies native Claude
Code's entry (project approval required). Shared context rules are in `AGENTS.md`.
The proxy JAR is copied into `tools/burp/`, not loaded from an external download.
Method grants, manual race/callback workflows and remaining enforcement limits are
documented in [`recon/README.md`](recon/README.md#explicit-method-grants-and-shared-burp-mcp).

**Dedicated visible browser:** `python3 tools/browser/launch.py` opens the prepared
private profile under `.recon/browser/` through Burp's web proxy on port 8080.
Browser-control connection and HTTPS capture/trust are still pending; see
[browser workflow](.claude/skills/scope-policy/references/browser-workflow.md).

**Taking over the project?** Start with [`Handover.md`](Handover.md) — the complete
setup explained file by file. Model routing policy (DeepSeek V4.1 Flash primary,
fallback contract, authorship audit): [`docs/model-routing.md`](docs/model-routing.md).

## Status

- [x] Plans 1–4 (architecture, modules, recon levels, vault design)
- [x] Corpus analysis (10,094 reports)
- [x] Vault seed (85 dossiers + index + Layer-1 CSV)
- [x] Supplemental report-index ingestion with pinned snapshots, deduplication, and provenance
- [ ] `30-Bug-Classes/` playbooks (seed from mind-hunt skills)
- [ ] `00-Engine/` doctrine + agent prompts
- [ ] KB-expansion pipeline implementation (docs/kb-expansion-pipeline.md)
- [x] Recon engine (`recon/`): scope-enforced, event-driven, freshness-ranked; ARTEX recon ideas ported (see recon/README.md)
- [x] One skills folder (`.claude/skills/`): 8 recon guides + 18 hunting skills (including partial cloud, takeover, business-logic, race-conditions and 5 auth), tested
- [x] Injection program (field ledger + trigger-matrix completeness gate, canary propagation map, per-host WAF profiles, payload context packets with model attribution, blind-XSS correlation on shared callback primitives, html-injection/ssti classes + 4 chain templates, three-question realism gate on completed chains, Burp/OpenAPI import adapters)
- [x] CSRF program (`hunt-csrf` + `recon csrf`): per-origin action × context × case ledger with fieldless/GET/GraphQL/realtime actions, 15 case families and 68 variants, facet-scoped reopening, value-free HAR/Burp/OpenAPI capture metadata, and an owned-loopback two-origin Chromium lab
- [x] SSTI detection subset (`hunt-ssti` + `recon ssti`): inert arithmetic/control probes per captured role/tenant/workflow context, independent raw render-surface evidence, ordered submission-receipt correlation, integrity checks, and offline grant-gated `cred-read`/`token-use`/`lateral` evidence with medium/high/critical ceilings; no native credential use, request execution, lateral movement or engine-level identification.
- [x] Access-control and mass-assignment offline workflow (`hunt-access-control`, `recon authz`, `fields diff`): nine case families, DELETE candidate seeding, fail-closed grant labels, exact captured contexts, hash-bound evidence and owned-loopback validation. This is not a live tester or a confirmed-finding engine.
- [x] File-upload lifecycle workflow (`hunt-file-upload` + `recon upload`): per-request sinks incl. signed storage, resumable and URL import; 24 lifecycle cases; artifact-backed accepted/stored/processed/served/executed/effect facts; owner-log layer attribution; callback ladder; one shared declared budget; stop rules and cleanup receipts; inert fixtures; Gate A offline and Gate B owned-loopback tests. No upload executor, payload or bypass-variant generator, and no live target was contacted.
- [x] Partial offline business-invariant/race workflow (`recon logic`, `recon race`): typed owned invariants, anomaly leads, exact-writer scenarios, bounded attestation imports and one deterministic owned-loopback collision. No synchronized target sender, complete B02–B18 fixtures, Gate C evaluation or live pilot.
- [ ] First campaign folder
- [x] Offline takeover workflow (`hunt-takeover`, `recon takeover`): typed DNS/referral/wildcard capture import, stale-host history, conditional trust ranking, provider status freshness, claim dossier and cleanup evidence. Owned simulation only; no live DNS collector, automated claimer or demonstrated live chain. See `plans/subdomain-takeover.md` for acceptance limits.

## License

MIT — see LICENSE. Third-party report metadata and referenced reports retain their
original terms; inclusion does not relicense upstream material.
