# Shared invariant contract

`recon/invariants.py` accepts a finite schema-1 JSON declaration: `workflow`
(`key`, `revision`, `policy_source`, `policy_status`, `states`, `edges`),
`operations` (exact URL/method/selector/fields/representation, touches edges),
`resources` (owned/shared/disposable), `invariants` (BL family, rule, resource,
oracle, typed predicate, deadline, cleanup), and optional `lab_contexts` for
exclusively loopback operations. Lab contexts are **not captured live identities**.

`declared`/`documented`/`owner-confirmed` are policy contract labels;
`inferred-observed` and `unknown` permit leads only. Predicates include allowed
transition, prerequisite before effect, at-most count, bounded quantity,
conservation by unit, refund capacity, intent idempotent effect, binding equality,
terminal-state consistency and version-current-at-effect. Unsupported owner rules
remain review-only; no expression/eval/SQL/templates in declarations.

Amounts use checked integer minor units or bounded exact Decimal strings with
explicit currency/exponent. State whether a displayed value is cache/UI/replica or
authoritative. Never derive a business rule or monetary severity from a response
status, arbitrary API parameter, scanner claim or owned-lab fixture alone.
