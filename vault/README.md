# bugvault — the hunting knowledge base

Obsidian vault (plain markdown, git-versioned). AI agents read/write these files
directly — no API needed. See /private/tmp/plan4.md §7 for the full design.

## Current state

- `35-Report-Studies/` — 85 dossier notes (`rs-<h1_id>.md`) of top-voted, bounty-paid
  HackerOne reports + `_MOC.md` index. Each: attack narrative, why-it-paid, technique
  links, evidence flags, full report text.
- `_data/reports.csv` — Layer-1 index: all 10,094 disclosed reports from HackerOne's
  official dataset (id, title, class, team, bounty, votes, body_chars).

## Planned (not yet created)

- `00-Engine/` doctrine, model routing, agent prompts
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
