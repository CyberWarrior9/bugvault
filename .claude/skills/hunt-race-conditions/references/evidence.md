# Causality and source-qualified receipts

Race run JSON names `scenario`, `schedule`, `outcome`, `impact_tier`, ordered
`members` (exact operation/context/intent, per-member marker and receipt ID for
measured outcomes), plus concurrent denominators and optional attestation ID.
Observed invariant breach still needs authoritative before/after/oracle,
projections, distinct satisfying control, marker and fresh replay. Inferred owner
policy cannot yield an observed violation. One success response or a client
clock timestamp never establishes commit/effect order.

The M5a attestation is operator-declared `burp:` external attempt count, separate
from member `imported-burp-capture` rows. A request ID must actually exist with
that capture basis and match each member's method, path and labelled actor. No
native relabel, no charge of historical imports as new sends. Ambiguous effects
stay spent/pending until reconciled; unresolved cleanup prevents ledger resume.

If a serial run also violates the rule, classify sequential-primary. Only matched
serial and fixed controls plus fresh replay and evidenced lab release can yield
race-eligible; this remains operator evidence for a human validator. A live
operator attestation by itself yields schedule causality **unresolved**, never
automatic exploitation or a target finding. Hash verification detects tampering,
not falsified operator statements.
