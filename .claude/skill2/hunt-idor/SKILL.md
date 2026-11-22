---
name: hunt-idor
description: "IDOR/BOLA/BFLA hunting for authorized BugVault campaigns: substitute object and identity references across path, query, body, header and GraphQL locations; climb a staged depth ladder from direct A-to-V swaps through request-shape variants, vertical and cross-tenant checks, write/delete proofs and chain targets. Use for every coverage row of class idor-bola and for any endpoint whose object identifiers change between accounts. Two test accounts only; browser/Burp is the default, with campaign-approved native requests and operator-run scanners permitted."
license: "MIT; original BugVault workflow. Technique matrix adapted in part from 0xN0RMXL/BugBountySkills (MIT); pinned blobs and exclusions in references/techniques.md"
metadata:
  implementation: "recon/report.py idor_candidates; recon/score.py idor-bola seeding"
  reviewed: "2026-11-12"
---

# Hunt: IDOR / BOLA / BFLA

Broken object-level authorization is the most common paid class on modern APIs.
The test is always the same shape: **A's session, V's object, a marker that proves
whose data came back.** Everything else is where the ID hides and how the request
is wrapped. A 200 without V's marker proves nothing; a 403 without a working
A→A control proves nothing either.

## When this skill applies

- `coverage.md` shows a row of class `idor-bola` — `recon/score.py` seeds it for
  `id_params`, `{id}`-shaped paths and GraphQL endpoints, and prints this skill
  in its `skill` column.
- `recon.md` lists **comparison groups** from `idor_candidates`: the same
  parameter name observed with **different values** under two accounts. That is
  your pre-built A/B pair — the exact endpoint, method and parameter to swap.
- Your own HAR imports show object IDs that differ per account (`orderId`,
  `invoice_id`, `userId` in path/query/body), or GraphQL queries taking node IDs.
- A response from A's objects embeds **other** identifiers (customerId, ownerId,
  documentId) — each is a new object reference to test.

Not every ID is authorization-relevant: public-by-design profiles, share links
and signed URLs are intended access. Confirm with V's private marker before
treating an ID as a boundary.

## Before the first request

1. Read `scope-policy`; confirm the class is not in `excluded_bug_classes` and
   the endpoints are in scope. Write methods (PUT/PATCH/DELETE) need their
   explicit `policy.allowed_methods` grants and only run on disposable objects.
2. Create two test accounts you control: **A** (attacker) and **V** (victim),
   one pair per role/tenant you compare. Put a unique marker in V's profile and
   in every V-owned object you test (`canary_idor_<8 random chars>`), so reading
   V's data is provable and distinguishable from A's own.
3. Import both accounts' browsing as HAR with account/role/tenant labels —
   `idor_candidates` is built from those labels.
4. Use the dedicated visible browser through Burp by default (see AGENTS.md and
   the browser workflow reference). A standing campaign execution plan can permit
   native checks with `python3 -m recon send` and bounded operator-run scanners,
   following `scope-policy`. Scanners remain aids, not confirmed IDOR evidence;
   missing browser access or a failed policy check is not permission to fall back.
5. **Never enumerate other real users' objects.** Adjacent-ID sampling
   (`id±1`) is only for objects owned by A or V, or under a program allowance.
   Random-tenant spraying reads real users' data and burns the engagement.

## The object and identity inventory (before any swap)

For each candidate endpoint, record for both A and V:

- Every location an object reference appears: path segment, query param, JSON
  body field, form field, header (`X-User-ID`, `X-Account-ID`, `X-Tenant-ID`),
  cookie, GraphQL variable/node ID.
- The **ID type**: sequential int, UUIDv4 (opaque), UUIDv1 (timestamp+MAC —
  predictable), base64 of something, application hash, composite (`user:doc`).
  Decoded/encoded forms are interchangeable substitution material.
- Every identifier embedded in responses (A's invoice containing `customerId`)
  — secondary references are the most commonly forgotten authz check.

## Test recipe (staged — climb in order)

### Stage 1: direct horizontal swap (read)

1. Control: A's session → A's object. Must succeed; keep the capture.
2. Negative control: no cookie/token → A's object. Must fail (else it is a
   missing-auth finding, not IDOR — different class, report that instead).
3. The test: A's session → V's object ID, same method, same shape.
4. Proof: response contains **V's marker**. Record both artifacts.

### Stage 2: request-shape variants

If the direct swap was refused, the check usually lives at one layer — vary the
request's shape, not its meaning. Full matrix in
[references/techniques.md](references/techniques.md): move the ID between
path/query/body/header; add the parameter the endpoint never asked for
(`?user_id=<V>`); wrap it (`{"id":[x]}`, `{"id":{"id":x}}`, duplicate keys,
parameter pollution in both orders); swap type/encoding (numeric ↔ string ↔
UUID ↔ base64 ↔ extension `.json`/`.xml`); alias paths (`/me/../<V-id>` where
`/me` authorizes then the path normalizes); change method per grant (including
override headers where the program allows); drop to an old API version
(`/v1/` siblings the engine already flags). One variation per attempt, with the
A→A control repeated when anything else changes.

### Stage 3: vertical and cross-tenant (BFLA)

Same substitution discipline, different boundary: A's regular token against
staff/admin **function** endpoints (including methods the UI never exposes but
the router serves), and A's tenant context against objects under V's tenant
with tenant/org parameters swapped alongside. Compare across session tiers you
are permitted to hold (free/pro/admin/staff) — a tier pair is a new context,
not a new endpoint.

### Stage 4: write and delete IDOR

Only with the method grants and only against V's **disposable** objects.
PUT/PATCH/DELETE V's object from A's session; prove impact by having V observe
the change (A renames V's marker object). Watch for mass-assignment adjacency
on the same endpoints (`role`, `tenantId`, `userId` fields in the body) — that
is its own class; link, don't conflate.

### Stage 5: chain what you proved

The object type decides the bounty, not the swap. Priority targets:

| V's object type | Chains into | Link with |
|---|---|---|
| Password-reset / magic-link / session objects | ATO | `yields-access` |
| Invoices, exports, reports | PII / financial disclosure | `enables` |
| Tickets, messages, internal notes | Cross-user PII, staff data | `enables` |
| API keys / token objects | Credential exposure → chained access | `yields-token` |
| Files / attachments | Private storage → further objects | `yields-id` |
| Tenant/org settings | Cross-tenant takeover (hint already in findings.md) | `escalates-via` |
| Webhook / integration config | SSRF adjacency → `hunt-ssrf` | `pivots-to` |

`python3 -m recon finding link` every proven edge; half chains stay parked as
leads with evidence retained.

## Recording and depth discipline

- Context is (endpoint × method × object type × tier/tenant) — a pass on one
  context tests nothing about another. The generic three-attempt rule applies
  per endpoint × class: three genuinely different variants, then record
  `tested` with what shape family was exhausted.
- `observed` outcomes go through the validator's gate: reading V's marker is
  real-person harm (gate 1). "Could read" without the marker is nothing.
- Never widen scope, never touch real users' objects, never spray tenants.
  Autorize/AuthMatrix diffing may be run by the operator in Burp as an aid; the
  proof is still the controlled A→V marker capture, not an extension's badge.

## Hard limits

- Two (or tier-paired) operator-owned test accounts only; no real-user data.
- Enumeration bounded to A/V-owned objects; adjacent-ID sampling never against
  strangers' IDs.
- Write/delete tests only on disposable V-owned objects with explicit grants.
- Live tests use the dedicated browser through Burp by default; campaign-approved
  native checks and operator-run scanners are permitted within their recorded limits.
  No autonomous runners, no scope widening, no bypassing failed scope/rate/budget checks.

Source provenance and what was excluded from the adapted checklists:
[references/techniques.md](references/techniques.md).
