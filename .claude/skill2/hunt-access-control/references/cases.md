# Case paths and near misses

All routes, methods and test contexts below are examples, not targets or grants.
Start with a captured operation and test-owned marker. The useful comparison
changes one dimension at a time; a weaker sibling is an inferred lead until it
produces a controlled unauthorized effect.

| Family | High-value question | Stop or handoff |
|---|---|---|
| Unauthenticated | Does a no-credential request expose an A-owned protected marker? | Public docs, unauthenticated error page, or a 200 with no protected content are not proof. Token parser flaws belong to auth. |
| Role | Does a supplied low role reach a supplied high-role function in the same tenant/workflow? | A different tenant or object ID is not a vertical comparison. |
| Tenant | Does a non-object collection/function use the wrong tenant when A/B issued contexts differ? | V-owned object ID substitution belongs to `hunt-idor`; a signed claim is not editable input. |
| Method | Does a captured or granted override route to a handler that skips the policy? | `_method` and override headers are **variants**, not permission; check both effective method and side effects. |
| Version | Does an in-scope old API mount perform an owned action rejected by the current route? | A guessed `/v1/` is unrequested without `sibling-expand` and its own scope check. |
| Projection | Does filtering/sorting/expanding or a GraphQL field leak an owned protected field? | Counts/schema alone do not prove an unauthorized read; never infer a real user's value via prefix queries. |
| Transport | Does a batch inner operation or alternate accepted MIME lose policy enforcement? | A parser error, content-type acceptance, or a different function is not proof. |
| Surface | Does a report/export/bulk path expose the same protected owned dataset? | Don't download a production export; use a test-owned marker and stop. |
| Mass assignment | Does a sent security-relevant property actually change a disposable owned record? | A field in an OpenAPI schema, 200 response, or DELETE without a field is a lead only. |

`ac-tenant` covers non-object scoped functions and collections; `hunt-idor` owns
all individual object-reference swaps in path, query, body, header and GraphQL.
Internal ID or GraphQL routes can seed both coarse classes. Group one fix under a
manual root key; split only for independently distinct policy boundaries/fixes.
