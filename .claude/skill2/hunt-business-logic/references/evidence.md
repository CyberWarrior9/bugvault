# Evidence and outcomes

`logic record --file` accepts JSON with `context`, `invariant`, `case`, `outcome`,
`impact_tier` and optionally channel, source-qualified `receipts`, typed `projections`,
`control_projections`, artifacts as `ROLE=campaign-relative-path`, marker,
control_marker, facts, attacker_gain and terminal/rubric. The CLI has no executor.

`observed` requires declared policy, authoritative projections violating a typed
rule, independent matched satisfying control, distinct before/after/oracle/control
artifacts and a fresh opaque attempt marker. The control carries its **different**
marker. An independent replay cites an observed parent and new fixtures/artifacts;
the finding lifecycle still requires separate replay and negative control.
`pending` is accepted/queued with unknown effect; timeout does not mean failure.
`blocked`, `inconclusive`, `skipped`, `not-applicable` need a reason. A 429, 5xx,
challenge, uncontrolled effect or unresolved cleanup stops the host in the ledger.

Source-qualified request IDs cannot be relabelled: `target-http` native,
`imported-burp-capture` Burp/browser, `owned-loopback` lab, and declared external
tool labels remain distinct. Redact artifacts **before** import; hashes detect
tampering, not forged source evidence. Operator-owned one-object terminal proofs
need readback and cleanup. Neither `observed` nor `T4` auto-creates a finding.
