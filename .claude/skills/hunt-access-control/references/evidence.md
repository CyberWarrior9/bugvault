# Evidence, status and privacy

`recon authz` is offline. A case is keyed to one exact path and value-free query
name shape (`?filter=`), method/selector, and captured account/role/tenant/workflow/
auth/representation. Concrete path variants never share observations without an
exact captured path. `UNKNOWN` labels are
isolated, not pooled. `plan` gives readiness and optional probe grants; `status`
shows open, stale, blocked and coarse-row conflicts. A negative applies to one
variant/context, not the whole class. An inferred sibling is not a capture.

For `observed` or `negative`, supply `--marker` (16–96 characters),
`--proof-basis`, at least one declared request, and distinct campaign-relative
`baseline`, `test`, `control` files. Baseline and test contain the owned marker;
control must lack it. A write proof additionally needs `before`/`after`
owned-state captures (an unchanged state is valid for a negative); for a deletion,
the before readback may contain the marker
while after shows its absence. Independent replay and causal validation remain
with the validator. A 200 or a hash match alone cannot establish a vulnerability.

The engine refuses obvious raw secret signatures and requires a `[redacted]`
indicator for sensitive proof. These checks are **not a general DLP scanner**;
the operator must minimize and redact any real secret or PII before importing an
artifact. Hashes are kept under `.recon/authz-evidence/`, and `verify` withdraws
integrity if files or policy/context facets change. `native:N` checks a stored
request ID against the same operation; `burp:label` is externally asserted.

`authz.probe_budget` counts *operator-declared* attempts for this ledger and is
not synchronized with Burp or recon's native budget. Manually reserve/reconcile
external requests against the standing campaign plan; never use this ledger to
bypass a failed `recon check` or rate/method/scope limit. Missing browser or
program allowance is `blocked`, not `n-a` or `negative`.
