make # Business-invariant / race acceptance ledger (2026-11-16)

This maps the *implemented checks*, not all promises in
[`plan_buisneess_logic_race2.md`](../plan_buisneess_logic_race2.md#102-gate-a-validates-the-offline-model-cli-and-attribution).
Run `.venv/bin/python -m unittest discover -s tests -q`. Only local or
`127.0.0.1` ephemeral listeners are used. These gates do not grant a target
send, and the fixtures cannot establish product policy, a live race or a bounty
finding.

## Gate A — offline contract: partial

| IDs | Checked assertion(s) | Remaining gap |
|---|---|---|
| A01–A03 | `test_recon_invariant_gate_a.py`: legacy coverage survives double init/future schema refusal; exact operation shapes, unknown captures, bounded JSON/cyclic/malformed state, symlink/path/unknown-key refusal | Full independent context-dimension migration matrix, every malformed reference and no-partial-write fault injection |
| A04–A06 | Exact currency exponent, integer/Decimal rejection, selected typed predicates/transition order; inferred BL-00 cannot adjudicate and passive live readiness is blocked | All rounding/allocation/unit rules, all workflow edges, full live labelled T0/T1 readiness matrix |
| A07–A09 | Imported IDs cannot be native; missing IDs fail, unknown delivery needs marker-bound owner commit trace + oracle, 5xx capture stops; independent observed/control artifacts, fresh marker; timing labels are not commit order | Full body/selector/transport variants and controlled wall-clock/response-order perturbation with authoritative transaction trace |
| A10–A13 | `test_recon_race_lab.py`: serial/fixed/trial/replay and independent cleanup; pending/unknown effect, ledger stop/resume, facet-specific stale history, hash tampering, stale race points withdrawn | Every async/compensation/retention and shared external-budget fault path; receipt authenticity is operator/lab provenance, not cryptographic attestation |
| A14–A16 | Existing `test_recon_skills.py`, `test_recon_logic.py`, `test_recon_race.py`: mappings, report/coarse conflicts, findings gates, CLI subsets/verify exit 2, no socket or subprocess during offline operations | Entire public CLI chain in one integration test, every candidate seeding/owner status case, exhaustive root dedup |
| A17–A20 | Source-labelled path/header signals, surviving sequence control escalation, run/point caps, denied success-rate key, constraint window classification | JS/stack tell examples, owner trace of a held constraint, genuine measured narrowing threshold (not fabricated from a serial schedule) |
| A21–A25 | Owned T2 write/T3 read/synthetic capped delta, shared-lineage T4, BL-00 closure, M5a two-member import with unknown member charged, A/V RC-21 and bounded four-writer lab | Every chain hint and 8-member M5a receipt matrix, terminal proof on a real authorized campaign, model judgment evaluation |

Tests: `test_recon_invariants.py`, `test_recon_invariant_gate_a.py`,
`test_recon_logic.py`, `test_recon_race.py`, `test_recon_race_lab.py`, plus
existing skill/config/report integrations. A fixture can be narrower than its
plan row; no A row is an endpoint-wide coverage claim.

## Gate B — lab scenario inventory: partial acceptance

| B IDs | Fixture / evidence path | Limit |
|---|---|---|
| B01 | Two-party HTTP loopback vulnerable/fixed/serial/replay, disjoint slot and legitimate same-key replay | Application fixture only |
| B02, B05, B06, B10, B15 | In-process finite check/commit interleavings, vulnerable/fixed/both serial orders, authoritative effects; offline `LogicLedger.record` with independent fixed oracle, reopened verify/report and cleanup; B15 also declares four exact writers | No real database/isolation/queue engine; no in-process request IDs passed as native |
| B03–B04, B07–B09, B11–B12 | Finite, fake-clock/receiver/oracle assertions for quote binding, partial construction, key scope/expiry, duplicate/out-of-order delivery, timeout/abort and saga compensation, cache/response-order masking | Most are not imported as individual public ledger events; response reversal is a modelled ordering, not observed HTTP transport |
| B13, B15 | Four-writer loopback scenario: one send per selected writer at 2 and 4, fixed contrast, source-qualified member receipts, `1/2` and `3/4` concurrent excess-effect ratios; stale point removed from status | No measured **return-to-contract** threshold. Separate in-process 4-writer serial point is explicitly not a concurrency threshold. No M5b/M6 group sender |
| B14 | One owned synthetic field write with readback and a separate owned sensitive-field server-vs-UI fixture; T2/T3 ledger import and cleanup for T2 | Not a production field or live authority proof |
| B16–B17 | In-process entitlement→reserved action and owned A/V one-token→session effect; distinct synthetic access-control/ATO finding artifacts give lineage-gated, lab-only T4 rehearsals | B17's service schedule is in-process, not an HTTP RC-21 group; no live session or authorization finding |
| B18 | In-process synthetic ten-minor-unit credit, capped T2 `value-delta`; separate loopback race replay with fixed and serial controls, then synthetic business-logic credit handoff and lab-only T4 | Target-class synthetic finding is a lab artifact, not a reportable live finding |

The `OwnedCommerce` step scheduler is **not** a synchronized network primitive.
It has explicit check/write/commit/effect/ack traces, at most eight named
writers, no sleeps, no outbound fallback, no real money, and resets state for
every contrast. Loopback traffic is direct test-fixture traffic and does not
exercise `ScopedClient` budget enforcement.

## Gate C — fixture authoring done; judgment evaluation pending

`tests/fixtures/recon/business_race_judgment.json` contains 16 text-only
adversarial prompts with expected disposition, class owner and required
uncertainty/stop language. `test_recon_business_race_gate_c.py` verifies their
structure and critical skill handoff language. It does **not** run an LLM,
benchmark with/without skills, prove that the model gives those answers, or
claim an independent A/B evaluation. The prompts include two-200/one-effect,
UI lag, allowed idempotency, serial-primary, unknown policy, unowned IDs,
burst/guessing, absent browser, third-party payment, injected pacing advice,
attestation relabel, unrelated chain and upload lifecycle ownership.

## Corpus and go/no-go

`scripts/build_dossiers.py` maps three exact race weakness labels. A private
temporary build with `.venv`/`pyarrow` generated **89** dossiers and the same
selection of names as the existing dirty working tree; the existing `vault/`
files were not overwritten. Derived base CSV counts: 856 business-logic / 23
race-conditions (10,094 rows); merged CSV: 1,203 / 44 (15,443 rows). These are
weakness-label derivations, not vulnerability efficacy or bounty rankings.

**Go for further offline fixtures and human review; no-go for target race sends
or full Gate A/B certification.** M5a remains an operator-attested import and
M5b/M6 requires separate cross-process reservation/transport enforcement.
