# bugvault — the hunting knowledge base

Obsidian vault (plain markdown, git-versioned). AI agents read/write these files
directly — no API needed. See [plan4.md §7](../plans/plan4.md) for the full design.

## Current state

- `00-Engine/` — [doctrine.md](00-Engine/doctrine.md): the operating law every agent
  loads at session start (chaining-first, marker discipline, body-diff rule,
  blocked-means-data, evidence before claim).
  [local-analysis-chunks.md](00-Engine/local-analysis-chunks.md): the chunked prompt
  kit for running workflow analysis through a local Ollama model (export → chunk →
  JSON back; the model analyzes, the engine verifies).
- `35-Report-Studies/` — 85 dossier notes (`rs-<h1_id>.md`) of top-voted, bounty-paid
  HackerOne reports + `_MOC.md` index. Each: attack narrative, why-it-paid, technique
  links, evidence flags, full report text.
- `_data/reports.csv` — Layer-1 index: all 10,094 disclosed reports from HackerOne's
  official dataset (id, title, class, team, bounty, votes, body_chars).
- `_data/reports-merged.csv` — combined discovery index, deduplicated by report ID;
  preserves original fields and adds separately attributed reddelexc, codebygk, and
  BugBountySkills subdomain-takeover metadata (165 takeover-tagged report IDs,
  `bbtakeover_*` columns — AI-generated source claims, discovery pointers only).
- `90-Meta/sources/_MOC.md` — [all-source coverage, provenance, and trust notes](90-Meta/sources/_MOC.md).
  Each source is pinned to a Git commit and its raw CSV/JSON is archived with a SHA-256 checksum.

## Updating the expanded index

From the repository root:

```bash
python3 scripts/import_report_index.py --out vault
python3 scripts/import_report_index.py --out vault --source codebygk
python3 scripts/import_report_index.py --out vault --source takeover
```

Rerun either command after regenerating `_data/reports.csv`; all previously registered
sources are retained from validated snapshots. Existing dossiers and the original
index are never changed by this importer. Only metadata/links are added, not full
report bodies. `source-indexed` and `not-reproduced` explicitly distinguish imported
references from independently validated findings. Unknown bounty amounts stay unknown.
The `codebygk_*` columns preserve historical source metadata, including severity,
asset type, and dates; `Closed` is not treated as proof of a resolved or valid finding.

## Planned (not yet created)

- `10-Campaigns/` per-engagement folders (scope.md, coverage.md, findings/)
- `20-Targets/` per-target dossiers
- `30-Bug-Classes/` playbooks — the `[[class]]` links in dossiers currently point to
  notes that don't exist yet; creating them resolves the graph
- `40-Payloads/`, `50-WAF-Bypasses/`, `60-Lessons/`, `70-Tools/`, `80-Reports/`, `90-Meta/`

## Conventions

- Dossier frontmatter is the query layer (Dataview/Bases): class, stack, team, votes,
  primitives, evidence flags
- `[[rs-*]]` = report dossiers; `[[class]]` = bug-class playbook notes
- Sensitive values in H1 reports are already redacted by HackerOne (████ blocks)
