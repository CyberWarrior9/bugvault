---
name: hunt-sqli
description: "SQL-injection hunting for authorized BugVault campaigns: error-based, boolean-blind, time-based, out-of-band and second-order variants across every input field from the input census, with a differential-pair method (probe vs negative control) that proves injection causally, a detection-mapping ladder that identifies exactly how the WAF or parameterization blocks payloads before any variant is designed, and chain targets (auth bypass, credential-extraction proof, file read, OS interaction). Use for every coverage row of class sqli and whenever a database error, differential or timing anomaly follows an input."
license: "MIT; original BugVault workflow"
metadata:
  implementation: "recon inputs census + fields ledger/matrix/fingerprint/packet; recon waf profiles; recon send executor; recon fact check for differential proofs"
  reviewed: "2026-11-13"
---

# Hunt: SQL injection

Injection is proven by a **differential**: the same request shape returning
verifiably different data depending on a condition you control — with a
negative control that fails when the condition is absent. Not by error strings
alone, and never by a payload list.

## When this skill applies

- `coverage.md` rows of class `sqli` (seeded for every parameterized endpoint).
- Any 500 with a fragment of your input in it, a DB-flavored error banner, a
  consistent boolean difference, a repeatable delay, or sorting/filter behavior
  that follows injected syntax.
- Numeric and date parameters (implicitly quoted contexts) and every
  `ORDER BY` / sort / column-choice parameter — the classic unparameterized spots.

## Step 1 — the input census and the field ledger (no field skipped)

`python3 -m recon inputs <campaign> --asset-id N` lists every observed input
with locations, methods, accounts, ID-likeness and stored-probe receipts;
`python3 -m recon import-burp <campaign> <export>` closes the header/cookie gap
(names only, values dropped). Seed and drive the **field ledger** with
`recon fields sync` / `recon fields record --state ...`:
`untested → probed → variant mapped → verdict`; the three-attempt rule applies
per variant family only after the rule map makes attempts genuinely different.
Fields whose values land in
`ORDER BY`, `LIMIT`, table or column names, and JSON/XML fields concatenated
into queries get their own rows — they break when quoted contexts don't, and
vice versa. Before any negative verdict check the module's **trigger matrix**
(`recon fields matrix --module <family>`): sort/bulk/export shapes are exactly
where unparameterized queries hide, and `recon fields claim --state full` is
refused while cells are missing.

## Step 2 — the detection ladder: map the defense first

One probe at a time, each with a marker (`canary_sqli_<8 rand>`). The engine
emits the ladder and keeps the receipts: `recon waf plan --host H` (bounded
single-then-pair probes with unique markers), then classify/record each
response with `recon waf observe` / `recon waf record --outcome ... --location
query|json|form|multipart|header|path` — the per-host element table (allowed /
blocked / stripped per location) is the map the variants are designed against.

1. **Baseline pair** — the request as-is, twice: establishes normal response
   bytes and timing jitter. Without this, differentials are unprovable.
2. **Syntax probes** — quote (`'`), double-quote, backtick, paren, comment
   terminators (`--`, `#`, `/*`) in the field's native type context (numeric
   fields get unquoted syntax, strings get quoted). Observe: DB error (which
   dialect?), HTTP 403/WAF page (which tokens triggered it?), silent
   normalization, no change.
3. **Classify**: parameterized (no differential at all), input validation
   blocklist, WAF inspection page, error-leaking parser, or candidate
   injection. Record the exact trigger token per class — that is the map.
4. **Design variants against the map**: for token blocklists, encode/split the
   specific blocked token (case, comment interleaving, URL/unicode layers —
   only the ones step 2 showed pass); for WAF pages, mismatch WAF vs database
   parsing (inline comments, nested terminators); for dialect confusion, the
   terminator set from step 2's error tells you the dialect.

## Step 3 — variants, in this order (cheapest signal first)

| Variant | Method | Proof standard |
|---|---|---|
| **Error-based** | syntax probe that triggers a DB error echoing your marker or version | error text bound to the stored response via `fact check body_contains_raw`; identify dialect/version, then `recon fields fingerprint --asset-id N --kind db "<dialect/version>"` so every later packet carries it |
| **Boolean-blind** | condition pair: `... AND <cond>` with `1=1` vs `1=2` (context-adjusted) | two stored responses differing exactly as the condition dictates **and** a negative control (original value) — three captures |
| **Time-based** | bounded delay (`≤10s` per the hunter brief) only when no observable differential exists | delay repeats on the condition and is absent on the control; never large sleeps |
| **Out-of-band** | DNS/HTTP callback to an approved receiver (same receiver discipline as `hunt-ssrf`) | callback correlated to the exact request, window-bounded |
| **UNION / result-shape** | only after a proven injection: column count via ordering, NULL-padding | one row of harmless test data or version banner — enough to prove read |
| **Second-order** | value stored now, executed by another flow later (report exports, admin search, batch jobs) | marker traceable through both requests |
| **Stacked / write** | multiple statements — only where the map proved separation works | **program-allowance gated**, like hunt-ssrf's depth grants; destructive statements never |

Extraction discipline once injection is proven: `version()`/`current_user`-
level banner or **one** harmless test record is the reportable proof. Bulk
dumping of other users' data is not performed — its feasibility, demonstrated
minimally, is the finding.

## Chains

| Proven primitive | Chains into | Link |
|---|---|---|
| Auth-bypass injection on login/lookup | session as another principal → ATO (`sql-authbypass-admin`) | `yields-access` |
| Credential read proof | account takeover via password reuse (demonstrated on test accounts only) | `yields-token` |
| Read primitive on a users/roles table | admin-account access | `escalates-via` |
| File-read primitive (dialect file functions, where authorized) | source/config exposure → further creds | `yields-id` |
| Stacked/OS interaction (allowance-gated) | RCE-equivalent impact | `escalates-via` |

`recon chain status` ranks the chain once edges are linked — and a fully proven
chain stays parked until the three realism questions (`recon chain realism`)
carry evidence-backed answers.

## Hard limits

- Differentials need the triple (probe, condition-flip, control) stored —
  `fact check` binds each to its response ID.
- No destructive statements (`DROP`, `DELETE`, `UPDATE` on shared data), no
  mass extraction, no disabling rate limits; delays ≤10s; one harmless test
  record maximum.
- Test accounts and program-owned data only; a production user table is proven
  reachable, never dumped.
- Live tests originate in the dedicated browser through Burp; sqlmap and
  similar runners are not dispatched by this engine — the map-and-design
  method replaces them.
