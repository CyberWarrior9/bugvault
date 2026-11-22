# Owned simulated provider rehearsal

Use a deterministic in-memory fixture or an explicitly owned loopback software lab
to exercise evidence handling when a real provider/path/grant is unavailable. This
is a software rehearsal, not permission to register a name, allocate a public
address, change a real zone or test a cloud provider. No live implementation or
provider client is bundled with this skill.

## Declare the boundary first

Name the fixture/lab owner, reserved synthetic hostname, resource/account labels,
marker/control, simulated API semantics and storage location. Keep it distinguishable
from every real campaign/provider and from the dedicated browser's live traffic.
Do not resolve the reserved name externally. Normal owned-loopback unit tests are
separate from browser website actions; prefer an in-memory fixture if no local
transport is needed. Do not start a service, install software or claim to have run
the rehearsal just because this reference describes it.

## Lifecycle to exercise

1. **Deploy A.** In the simulator, bind an owned resource to the synthetic hostname
   and show its original inert content. Preserve declared simulated DNS/trust context.
2. **Delete A.** Remove the resource while leaving only the simulator's dangling
   reference. Preserve time and the simulated unclaimed response. Confirm an
   independently owned still-bound resource cannot be reclaimed by the other lab
   account; refusal is the negative claimed-resource case, not a production result.
3. **Precheck and namespace.** Before simulating reclaim, record the conditional
   trust references and the exact simulator availability/ownership requirements.
   Preserve what is synthetic, unknown or not modelled.
4. **Reclaim as B.** Bind a second owned simulated account/resource and serve only a
   unique inert marker. Record a no-marker baseline, candidate-host after response,
   fresh replay and a separate owned control marker/result. A simulated provider
   resource URL alone does not stand for the program hostname.
5. **Release and check.** Remove B's binding/resource, record the exact simulated
   release receipt and post-release marker absence. Track a failed release and
   unresolved cleanup separately; cleanup must not be inferred from test teardown.

Hash preserved artifacts and bind chronological stages to the same candidate and
owned resources. Import only with the installed wire schema. If reviewing a written
fixture rather than executing a lab, report a **rehearsal plan or supplied log review**,
not an executed test, marker retrieval or successful integrity check.

## What this can and cannot establish

It can exercise deploy/delete/reclaim/marker/release chronology, negative controls,
candidate provenance, precheck-before-claim rules, missing grants/path handling and
cleanup failure behavior in the local evidence workflow. Synthetic parent trust
observations can exercise conditional ranking, not a live trust exploit.

It cannot certify any real provider's namespace reuse, parent DNS delegation,
wildcard DNS behavior, DNSSEC, public TLS/certificate issuance, browser cookie/CSP/
CORS behavior, OAuth acceptance, mail control or a live downstream chain. A fake
`TLS valid` field is not a browser/certificate test. Keep real-provider rehearsal,
connected browser/Burp checks and a scoped live pilot as separate human-approved
follow-on gates. A passing lab never changes a candidate into finding `confirmed`.
