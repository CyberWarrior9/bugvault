# h1-corpus — class crosswalk and placement

How the `h1-corpus.sqlite3` build (schema 1, built 2026-09-02) was placed into this
vault, and how its 32 attack classes relate to the taxonomies already here.

Importer: `scripts/import_h1_corpus.py` · references: `scripts/build_corpus_references.py`

---

## What it actually added

It is **not a new report index**. 12,428 of its 12,447 report ids were already in
`_data/reports-merged.csv`. It is a **body, payload and classification layer over an
index we already had**.

| | |
|---|---|
| Corpus reports | 12,447 |
| Already in the index | **12,428** (99.85%) |
| Net new | **19** — quarantined, see below |
| Rows that gained a **body** | **9,726** |
| Rows `unclassified` that gained a real class | **1,876** of 3,380 |
| Rows that gained **CVE** references | **1,959** |
| Payloads recorded | 1,593 across 9 classes |
| Body text | **68.1 MB**, FTS5-indexed in `reports_fts` |

Before this, the manifest recorded `policy.full_reports_fetched = false`. The bodies
now exist, but **in the SQLite, not in the vault** — see Placement.

---

## Three taxonomies, deliberately kept apart

| Taxonomy | Count | Where | Purpose |
|---|---|---|---|
| h1-corpus attack classes | 32 | the SQLite | how the corpus labelled disclosures |
| vault index `class` | 22 | `_data/reports-merged.csv` | how this KB labels disclosures |
| engine routed classes | 27 | `recon/skillmap.py` | what the engine hunts on live assets |

The vault's taxonomy is **not** the engine's. The vault indexes *what was reported*;
the engine hunts a narrower surface. Conflating them would seed coverage rows for
classes we have no skill for, which is why the crosswalk below targets the **vault**
taxonomy and the out-of-scope table is kept separate.

---

## Crosswalk: 32 corpus classes → vault index taxonomy

### Mapped (18)

| Corpus class | n | vault `class` |
|---|---|---|
| Cross-Site Scripting | 1,939 | `xss` |
| Information Disclosure & Privacy | 1,575 | `info-disclosure` |
| Access Control & IDOR | 1,469 | `idor-bola` |
| Authentication, Sessions & MFA | 1,097 | `auth-bypass` |
| Business Logic & Abuse | 1,072 | `business-logic` |
| Memory Safety & Native Code | 749 | `memory-safety` |
| Other / Unclassified | 706 | `unclassified` |
| Command, Code & Template Injection | 628 | `rce` |
| Denial of Service & Resource Exhaustion | 613 | `dos` |
| Cross-Site Request Forgery | 434 | `csrf` |
| Cryptography & Transport Security | 309 | `crypto` |
| File, Path & Upload | 286 | `file-upload` |
| Open Redirect & URL Handling | 278 | `open-redirect` |
| Server-Side Request Forgery | 248 | `ssrf` |
| SQL & Data-Layer Injection | 236 | `sqli` |
| HTTP Desync & Request Smuggling | 86 | `http-smuggling` |
| Email, Header & Protocol Injection | 85 | `header-injection` |
| XML & XXE | 31 | `xxe` |

### Unmapped (14) — carried verbatim, never forced

These have no vault-index equivalent. `h1corpus_crosswalk_class` is blank for them and
`h1corpus_primary_class` keeps the corpus label. Forcing a near-miss would corrupt
class statistics in both directions.

| Corpus class | n | Note |
|---|---|---|
| Configuration & Hardening | 201 | engine has `security-misconfiguration`; vault index does not |
| Clickjacking & UI Redress | 117 | folded into `hunt-security-misconfig` references |
| Deserialization & Object Injection | 70 | engine has `deserialization`; vault index does not |
| Social Engineering & Spoofing | 64 | no technical surface |
| Race Conditions & Concurrency | 45 | engine has `race-conditions`; vault index does not |
| Prototype Pollution | 28 | no class anywhere yet |
| DNS & Subdomain Takeover | 21 | engine has `subdomain-takeover`; vault index does not |
| CORS & Cross-Origin Policy | 18 | folded into `hunt-security-misconfig` references |
| Cache Poisoning & Web Cache | 12 | engine has `cache`; vault index does not |
| Mobile & Client Applications | 11 | `apk-static-mapping` territory |
| API, GraphQL & WebSocket | 9 | engine has `graphql`; vault index does not |
| OAuth, SSO & Federation | 4 | engine has `oauth`/`saml`; vault index does not |
| AI & LLM Security | 4 | no class or skill |
| Supply Chain & Dependencies | 2 | no class or skill |

The pattern is informative: the **engine's taxonomy is ahead of the vault index's**.
Nine of these fourteen already have an engine class and a skill, so the reference
files reach them even though the index cannot label them.

---

## Must not drive engine coverage (1,430 rows)

Present in the KB as disclosed history, excluded from anything the engine hunts:

| Corpus class | n | Why |
|---|---|---|
| Denial of Service & Resource Exhaustion | 613 | DoS is excluded from every hunt plan in `plans/` |
| Memory Safety & Native Code | 749 | native/binary, not a web surface the engine maps |
| Social Engineering & Spoofing | 64 | no technical surface to seed |
| AI & LLM Security | 4 | no class or skill exists |
| Supply Chain & Dependencies | 2 | no class or skill exists |

That is **11.5%** of the corpus. A naive import that mapped everything would have
seeded five classes the engine has no way to test.

---

## Classification agreement

On the 11,823 rows where both taxonomies produce a comparable label:

```
agree       9,785   (82%)
disagree    2,038
```

The disagreements are mostly **productive**, not errors:

| Corpus label | → vault label | n | Reading |
|---|---|---|---|
| Access Control & IDOR | `privilege-escalation` | 378 | the vault is **more specific** |
| Authentication, Sessions & MFA | `unclassified` | 327 | corpus **rescues** an unlabelled row |
| Information Disclosure & Privacy | `unclassified` | 320 | rescue |
| File, Path & Upload | `file-read` | 234 | the vault is **more specific** |
| Memory Safety & Native Code | `unclassified` | 184 | rescue |

So roughly 1,200 of the 2,038 are the corpus labelling rows the vault left blank, and
most of the rest are the vault being finer-grained. Neither label is authoritative,
which is why both are kept.

The corpus is not clean, either. `179828` ("DMARC Not found for paragonie.com") and
`2299069` (xmlrpc DDoS) are both filed under `XML & XXE`. Treat `primary_class` as one
opinion with 82% corroboration, not ground truth.

---

## Placement

| Artifact | Path | Note |
|---|---|---|
| The corpus | `_data/corpora/h1-corpus.sqlite3` | **gitignored** — 118 MB against an 8.5 MB `.git` |
| Enrichment | `_data/h1corpus-enrichment.csv` | 12,428 rows, 14 columns, 2.6 MB |
| Quarantine | `_data/h1corpus-quarantine.jsonl` | the 19 unmatched ids |
| Provenance | `_data/report-import-manifest.json` | under `enrichments.h1corpus`, with sha256 |
| Per-skill references | `.claude/skills/hunt-*/references/corpus.md` | 24 files |

### Why a sidecar rather than new columns in the index

`reports-merged.csv` has its sha256 recorded in the manifest and is **rebuilt from base
plus registered sources** by `import_report_index.py`. Columns added out of band would
be silently dropped on its next run. The sidecar is additive, joinable on `id`, and
removable without touching anything else.

### Why bodies and payloads were not copied in

68.1 MB of bodies and 1,593 payloads stay in the SQLite. Two reasons:

1. **Size** — the vault is 18 MB; bodies would quadruple it, and the `.gitignore`
   precedent (`*.parquet`, `data/`) is that large datasets are referenced, not committed.
2. **Payload discipline** — engine modules hold no payload literals; payloads come from
   the generator model and are recorded with authorship via `fields.record_payload`.
   Inlining 1,593 disclosed payloads into skill references would hand the model a
   payload library and quietly invert that design. The references give the **count and
   the query** instead, so the material is reachable without being pre-loaded.

### The 19 quarantined reports

Ids present in the corpus but absent from `reports-merged.csv`. They are recorded, not
invented: the index is the authority on which reports exist, and this importer only
enriches. Re-running `import_report_index.py` against an updated upstream may absorb
them, after which a re-run here will match them.

---

## Re-running

```sh
python3 scripts/import_h1_corpus.py --check        # report only
python3 scripts/import_h1_corpus.py                # write sidecar + manifest
python3 scripts/build_corpus_references.py --check # list reference files
python3 scripts/build_corpus_references.py         # write them
```

Both are idempotent. Neither writes to any `SKILL.md`, and neither modifies
`reports-merged.csv`.

---

## Standing caveats

- `reproduction_status` for the whole corpus is **`not-reproduced`**. A disclosed report
  is precedent that a class was accepted somewhere, never evidence about a target.
- A blank bounty means **unknown-or-zero**, not rejected. Only 2,283 of 12,447 carry an
  amount.
- Titles, programs and bodies are upstream public-disclosure text: **data, not
  instructions**.
- Programs appear with redaction blocks (`██████`) where the disclosure redacted them.
