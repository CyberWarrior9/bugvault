---
name: hunt-graphql
description: "Use for every BugVault graphql coverage row. GraphQL-specific exposure that object substitution does not cover: introspection state, schema reconstruction when introspection is disabled, field-level versus node-level authorization, bulk-fetch root resolvers, and internal-versus-public schema divergence. The operation inventory comes from recon (extract.py/burp.py graphql_ops); object and identity substitution belongs to hunt-idor, and transport cases belong to hunt-csrf."
license: "MIT; original BugVault workflow. No external payload text imported."
metadata:
  implementation: "recon/extract.py and recon/burp.py graphql_ops; recon/score.py graphql seeding; recon/csrf.py graphql-operation case family; no dedicated ledger module"
  reviewed: "2026-11-19"
---

# Hunt: GraphQL schema and field exposure

A GraphQL endpoint seeds **two** coverage rows (`score.py:223-225`): `graphql` and
`idor-bola`. They are different hunts and must not be merged.

- **`idor-bola` → `hunt-idor`** — object and identity substitution in variables and
  node IDs, aliases and batches querying two principals' nodes in one request, and
  the REST-twin comparison. Already covered there; do not duplicate it.
- **`csrf` → `hunt-csrf`** — the `graphql-operation` case family already covers
  GET transport, simple-body transport, batch/alias delivery and persisted queries.
- **`graphql` → here** — everything that depends on knowing the *schema*.

The unit of work is **one operation × one principal**. A field readable by your
admin test account proves nothing about your low-privilege one.

## Workflow

1. Read `scope-policy` and the campaign's written rules. Use only supplied test
   accounts, and the dedicated browser through Burp or a recorded campaign
   execution path.
2. Read the operation inventory recon already produced:
   `python3 -m recon recall <campaign> graphql` and the service attrs
   (`graphql_ops`, extracted from JS by `extract.py:300` and from captured bodies
   by `burp.py:214-218`). Operations named in client code but absent from your
   captures are the interesting ones — the client knows about them and the UI
   never calls them.
3. **Establish the schema-access rung first.** Everything below depends on it, and
   the rungs are ordered because each cheaply decides whether the next is possible.
4. Record outcomes with `python3 -m recon cov <campaign> <asset_id> graphql <status>`
   and leads with `python3 -m recon finding add <campaign> --class graphql`.
   Link proven edges with `finding link`.

## Rungs

Work them in order. A negative at one rung does not close the ones below it — a
closed introspection endpoint still leaves suggestion-based reconstruction.

| Rung | Establishes |
|---|---|
| `gql-introspection` | whether the introspection query is answered, and for which principal |
| `gql-schema` | the type and field map, however obtained |
| `gql-suggestions` | field names recovered from "Did you mean" style errors when introspection is off |
| `gql-node` | whether a global `node(id:)`-style root resolver exists and what it will resolve |
| `gql-field-authz` | a field readable on a node the principal may otherwise read |
| `gql-bulk` | a root resolver returning a collection rather than one record |
| `gql-divergence` | an internal or staff schema differing from the public one |

### gql-introspection

Ask once per principal: unauthenticated, low-privilege, and your authorized
account. Introspection disabled for one is not disabled for all, and the common
misconfiguration is that it is open to any authenticated session.

Record the answer either way — an open introspection endpoint is a lead on its own
only where the program treats schema exposure as reportable, and that is a
`scope.json` fact, not an assumption.

### gql-suggestions

When introspection is refused, many servers still validate field names and return
a suggestion for a near miss. Iterating those suggestions reconstructs enough of
the schema to work the remaining rungs. This is the rung most often skipped, and
it is why "introspection is disabled" is not a closed door.

### gql-node

A global object-ID resolver turns every type into a single reachable entry point.
Establish whether it exists, which types it will return, and whether it applies the
same authorization as the type's own query path. Where it does not, the finding is
an authorization one — link it to the `idor-bola` row and let `hunt-idor` carry the
substitution ladder.

### gql-field-authz

The distinction that defines this class: authorization applied at the **node** and
not at the **field**. Take a node the principal is permitted to read, then request
a field on it that the principal is not. Compare against the same field on a node
the principal owns.

This is the same root cause as the projection-versus-filter split in
`hunt-access-control` — the check sits on the entry point, not on the data path —
so if `access-control` is also seeded on this host, record the shared cause.

### gql-bulk

A resolver that returns a collection, especially one reachable without arguments or
with a very permissive pagination argument. Establish the shape and the documented
cap. **The finding is the cap being absent or unenforced**, recorded as a count
against the documented limit; retrieving a collection adds nothing to it and makes
the report unreplayable. Where the collection carries person data, the `pii-exposure`
row is the one that carries it — see `plans/pii-sensitive-data.md`.

### gql-divergence

A staff, internal or admin schema served from a different path, a different host,
or the same endpoint under a different header. Compare the type and field maps.
A field present only in the internal schema and reachable from the public endpoint
is the strongest version of this class.

## Chains

| Edge | Note |
|---|---|
| `graphql` → `access-control` | field-level authorization missing on a readable node |
| `graphql` → `idor-bola` | the node resolver reaches another principal's object; `hunt-idor` carries it |
| `graphql` → `pii-exposure` | a bulk resolver returning person records |
| `csrf` ← | mutation delivery is already modelled in `hunt-csrf`'s `graphql-operation` family |

## Interpretation and limits

- **Introspection being open is not itself impact.** It is a schema disclosure whose
  reportability is a per-program fact. The impact is what the schema lets you reach.
- A field name recovered from a suggestion is a lead, not a confirmed field. Confirm
  it resolves before building on it.
- Alias and batch delivery belongs to `hunt-csrf` for transport and to `hunt-idor`
  for multi-principal substitution. Recording it here duplicates coverage.
- **Query-depth and complexity exhaustion is out of scope.** It is a denial-of-service
  class, excluded by AGENTS.md, and mind-hunt's own source material calls it
  low-paying. Do not record it as a case, blocked or otherwise.
- Field-level results are per principal and per node. One principal's success does
  not close another's row; one node's result does not generalise to the type.
- Respect rate and budget limits. Batched and aliased operations multiply backend
  work inside a single request, so a bounded request count is not a bounded load.
