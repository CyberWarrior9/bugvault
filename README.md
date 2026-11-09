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
│   └── _data/reports.csv     # Layer-1 index: all 10,094 disclosed reports
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
for the seven capability guides, deduplication rules, actual agent counts (**zero LLM
agents**) and remaining execution-isolation limits.

## Status

- [x] Plans 1–4 (architecture, modules, recon levels, vault design)
- [x] Corpus analysis (10,094 reports)
- [x] Vault seed (85 dossiers + index + Layer-1 CSV)
- [ ] `30-Bug-Classes/` playbooks (seed from mind-hunt skills)
- [ ] `00-Engine/` doctrine + agent prompts
- [ ] KB-expansion pipeline implementation (docs/kb-expansion-pipeline.md)
- [x] Recon engine (`recon/`): scope-enforced, event-driven, freshness-ranked; ARTEX recon ideas ported (see recon/README.md)
- [ ] First campaign folder

## License

MIT — see LICENSE.
