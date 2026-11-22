# Scheduling contract

Declare schema-1 scenario with `workflow`, `invariant`, `context`, `family`,
`resource`, `order_matters` and `members` (operation, context, intent), optionally
the survived logic event and named control. Each member must name an in-scope exact
writer of that resource. A 3–8 member fan-out uses 3–8 **distinct** writers; two
members may intentionally name one writer with different intents. RC-21 requires
two separately labelled owned accounts and a one-time artifact resource.

Run schedules are `serial-ab`, `serial-ba`, `concurrent`, `fixed` and `replay`.
Every **measured** concurrent outcome supplies parallelism/attempts/successes
together; an unexecuted blocked/inconclusive review is not a measurement. Bounds
are at most five runs and three distinct parallelism points **per scenario**;
further attempts require a separately reviewed plan and remain blocked in this
ledger. A response rank is not a commit order. Lab barrier traces can demonstrate
local release; operator attestation declares a gate but does not prove application
overlap. Agents have no synchronized target send capability in this release.
