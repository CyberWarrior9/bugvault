---
name: hunt-access-control
description: "Hunt broken function/field/tenant access control and mass assignment on authorized BugVault campaigns. Load for every access-control or mass-assignment coverage row, including API routes without object IDs, internal/admin/export paths, GraphQL function/field policy and POST/PUT/PATCH/DELETE candidate writes. Build a sibling-path graph, compare controlled A/B roles and owned records across method, version, projection, transport and surface, then record offline grant-gated evidence with recon authz. Object-ID substitution belongs to hunt-idor."
license: "MIT; original BugVault workflow. No third-party technique text incorporated."
metadata:
  implementation: "recon/authz.py offline ledger; recon/fields.py diff; recon/score.py candidate seeding"
  reviewed: "2026-11-14"
---

# Hunt: access control and mass assignment

Pursue **critical effects first** on an authorized target, but never confuse a
candidate row with a policy failure. The engine only inventories and records; it
never sends requests, uses credentials, mutates records or promotes findings.
Read `scope-policy`, written program rules and the campaign's standing execution
plan before live work. Without a connected dedicated browser/Burp or a separately
approved execution path, do only offline inventory/owned-lab work. An absent
`authz` grant is a blocker, not permission to improvise another tool.

## Inventory → path graph → next safe test

1. `python3 -m recon authz sync <campaign>` reconciles captured/declared exact
   routes and contexts. `python3 -m recon fields diff <campaign> --module <module>`
   compares **sent** names to **declared** method-matched spec fields; it does not
   establish acceptance. Unknown role/tenant/workflow labels and inferred sibling
   URLs are not equivalent policy contexts.
2. `python3 -m recon authz plan <campaign> [--target N]` shows nine case cards per
   path/query-name shape × method × selector × representation × account × role ×
   tenant × workflow. A sibling
   edge is a hypothesis about the same protected function/dataset. Pair a real
   capture with a supplied A/B test account and a disposable owned marker. Rank
   hypotheses by the protected effect, not by a desire to close every row.
3. For one dimension at a time, collect an authorized baseline, unauthorized
   attempt, distinct negative control, and independent owned-state readback for
   writes/asynchronous effects. A 200, spec field, empty error or token-looking
   string is not an access-control proof. Use the minimum data needed; redact
   secrets/PII before writing evidence files. Never download a bulk dataset.
4. If an observed result unlocks a chain, record a separate, explicitly granted
   `token-use`, `lateral` or `persistence` rung with its parent event and fresh
   controls. Use test-owned tokens/resources only. No engine credential use or
   lateral execution; hand off to the existing finding validator/chain realism gate.

## Case ownership and proof

| Case | Comparison and boundary |
|---|---|
| `ac-unauth` | Protected captured A request versus no credential; a granted read-extraction probe may inspect an in-scope debug/docs surface. Public docs alone are a lead. |
| `ac-role` | Supplied low/high roles on the same non-object function; independent proof of a higher-role effect. |
| `ac-tenant` | Tenant-scoped collection/function **without an object-reference swap**; use only A/B-owned markers. Object-ID substitutions in path, query, header, GraphQL or token identity go to `hunt-idor` or auth owner. |
| `ac-method` | Another granted method/override against the same owned policy target. `Allow` is not proof; `method-matrix` grant for alternate shapes. |
| `ac-version` | Captured/declared in-scope old version compared with current. Inferred siblings need `sibling-expand`; discovery never widens scope. |
| `ac-projection` | Owned field/collection selection versus filter/sort/expand or GraphQL resolver; V-owned object read goes to `hunt-idor`. No real-user prefix extraction. |
| `ac-transport` | Same function through captured MIME/batch/GraphQL alias/REST twin; uncaptured shapes need `representation-fuzz` grant. |
| `ac-surface` | List/detail versus observed export/report/bulk surface for owned records; object-ID proof goes to `hunt-idor`. |
| `ma-privileged-field` | Captured POST/PUT/PATCH/**DELETE** candidate with an assignable field; disposable owned record, sent field plus **independent applied-state readback**. DELETE or status 200 alone is not mass assignment; `write-proof` is opt-in. |

The first eight belong to `access-control`; the ninth to `mass-assignment`.
GraphQL and internal ID routes can seed `idor-bola` too. Record the hypothesis
owner and link a shared root cause; do not file the same fix twice. The nine cases
evaluate critical signals (secrets, PII, admin effects, bulk data, topology,
config exposure); a signal raises priority, not confidence. Cloud metadata and
server-side fetching route to `hunt-ssrf`, token-validation to `hunt-auth-bypass`.
Read [case paths and near misses](references/cases.md) before choosing a variant;
read [evidence and status rules](references/evidence.md) before recording a result.

## Grants, budget and stopping

`scope.json` may grant `authz.probe_grants` (`method-matrix`, `sibling-expand`,
`representation-fuzz`, `id-mutation`, `read-extraction`, optionally `write-proof`)
and `authz.chain_grants` (`token-use`, `lateral`, `persistence`), with positive
`probe_budget.requests` and `per_host`. The defaults are empty and zero. A grant
is only an **offline ledger gate**, not a standalone authority to send traffic:
check `policy.mode`, `allowed_methods`, scope/exclusions, written rules and the
execution plan too. Burp/external request counts are manually reconciled; the
ledger's declared counts are not an enforced shared traffic budget.

Stop on lockout, 429, CAPTCHA, surprise side effect, cap exhaustion or no approved
execution path. Never enumerate strangers' IDs, forge signed claims, spray
credentials, send unsupported methods, probe discovered internal/out-of-scope
hosts or run destructive admin actions. Optional `write-proof` is limited to
disposable owned data, a method grant, before/after proof and agreed cleanup.
Read-only variants are capped by the campaign's lower limit (plan proposes at
most eight; `probe_budget.readonly_variants` can lower it); writes get one attempt
per owned marker/resource. `ac-unauth`, `ac-role`, `ac-tenant` and `ac-surface`
get one controlled variant per owned marker. No cap certifies class completeness.

Use a `matrix:`, `expand:`, `fuzz:`, `extract:` or `mutate:` variant ID only for
its corresponding probe family; the ledger requires the matching `--grant`.
For an override give the effective granted method, for example
`--variant matrix:PATCH:header --grant method-matrix`; the family grant alone
cannot authorize PATCH. A named GraphQL `query` over POST is read-only in this
ledger; untyped/persisted operations and batch POST stay conservatively
write-gated, even when the inner operation is a GET.
`write-proof` is also required for *all* write-method evidence, including a
function-level `ac-role` case on an ordinary POST. A granted method is not permission to
perform a destructive operation.

## Offline evidence commands

```bash
python3 -m recon authz record <campaign> --context 12 --case ac-role \
  --state observed --variant low-role --marker owned_marker_12345678 \
  --requests 3 --proof-basis 'A/B-owned marker and independent policy control' \
  --artifact baseline=evidence/authorized-redacted.txt \
  --artifact test=evidence/low-role-redacted.txt \
  --artifact control=evidence/wrong-resource-redacted.txt \
  --impact admin --note 'Owned test role reached the protected function'
python3 -m recon authz status <campaign>
python3 -m recon authz verify <campaign>
```

Each artifact is campaign-local and copied under `.recon/authz-evidence/` by
SHA-256; proof roles must be distinct and bind the test-owned marker. If a case
needs a probe grant, pass its exact `--grant` label. A chain rung additionally
needs `--parent <event-id>`. `native:<id>` references must be genuine matching
stored requests; `burp:<label>` is an external operator reference, not a native
fact. `observed` remains an operator assertion: validators must replay with a
fresh marker and negative control before confirming a finding. `n-a` is not a
shortcut for a missing capture or a bodyless DELETE. The field trigger matrix's
`full` claim is not authorization-test completeness. A `negative` is scoped to
one variant and stays on the open worklist; it cannot close a coarse class.

For manual root-cause deduplication, use `--root-key <short-label>` and
`--related-case <case>`; overlapping object-reference proof stays in `hunt-idor`.
If an attempt was recorded first, append its proof as a second event with the
same marker/variant and `--requests 0` (no new traffic). A chain rung needs a
**fresh** marker. The ledger validates artifact shapes and hashes, not the
operator's real-world authorization or the server's causal behavior.
