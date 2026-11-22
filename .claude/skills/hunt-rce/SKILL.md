---
name: hunt-rce
description: "Review terminal remote-code-execution evidence for authorized BugVault campaigns and source-qualified command-injection or deserialization coverage rows. Load when an exact process, template, upload processor, parser or worker sink could execute code, or another hunt claims an execution consequence. Use the offline RCE journal, owned-lab contrasts and independent validation; a callback, delay, status, parsed file or template arithmetic alone is never RCE. No payload generator or target executor."
license: "MIT; original BugVault workflow. Third-party sources linked, not copied."
metadata:
  implementation: "recon/rce.py offline candidate and lab receipt journal; recon/execproof.py syntactic assessment"
  reviewed: "2026-11-20"
---

# Hunt: RCE terminal proof

This skill does not grant target traffic,
execution, receiver use or access to server source. With no
connected observer, stay offline or on owned loopback fixtures. 

## Map before classifying

Use the owning skill for the entry: `hunt-ssti` for template evaluation,
`hunt-file-upload` for intake/processing, `hunt-ssrf` for fetches, `hunt-xxe`
for XML, `hunt-sqli` for database inputs and `hunt-access-control` for roles.
This skill governs their *terminal execution claim*, not their weaker primitive.
Trace exact actor, URL, method, field, decoding/storage/queue, worker, deployed
consumer and independent effect; record direct versus inferred edges. A browser
bundle's `eval` is not a server sink. A serializer-looking cookie does not show
that attacker bytes reach a deployed deserializer.

`python3 -m recon rce declare <campaign> --file evidence/sink.json` imports a
campaign-local source graph. An unqualified graph is a lead, not a coverage row;
source-supported graphs seed `command-injection` or `deserialization` as **untested**
on the exact in-scope endpoint asset. This is still an operator-supported claim,
not a code-dataflow or runtime verifier. Review the safe metadata with
`python3 -m recon rce show <campaign> --id N` and paginated `rce status`.
See [declaration formats](references/format.md).

## Assess a controlled observation

`python3 -m recon rce record <campaign> --file evidence/receipt.json` records
**offline or owned-lab** receipts only. Typed roles bind baseline, trigger,
fresh replay, a matched negative, a working positive, an independent effect and
cleanup. The conservative assessor rejects missing, declared-incomplete,
reflected and cross-attempt receipts, and requires actor/worker/object labels;
it cannot verify those labels are true. `eligible-for-validator` means merely
that a full *lab* bundle is syntactically reviewable. It does not say execution
occurred, the worker is real, the program permits the action or a target finding
can be confirmed. `rce verify` checks private retained evidence, original source
files and policy staleness; use all pages to audit the full journal.

Do call a callback, timing deviation, error, thumbnail, parsed XML or
arithmetic expression code execution. A one-shot server-only owned effect under
the lower-trust actor, fresh replay and a matched negative still need human
causality and authority review before BugVault's finding lifecycle can advance.
Do read environment variables, other users' files or cloud metadata merely
to upgrade severity. Preserve blocked/inconclusive cases and cleanup receipts.

Existing `hunt-file-upload` hard limits apply: no active/executable uploads,
polyglots, configuration overrides, web or reverse shells, destructive or
persistent effects. Do attempt gadget chains, memory corruption, WAF-bypass
payload ladders or unapproved internal/receiver traffic. Stop on 429/5xx,
challenge, unexpected side effects, third-party data or unresolved cleanup;
never switch transports to bypass a failed scope or budget gate. The separate
human validator applies replay, negative-control, reportability and actual
impact requirements; the RCE journal never promotes a finding.

Disclosed-report precedent for this class — scale, highest-bounty disclosures and
corpus queries: [references/corpus.md](references/corpus.md). Precedent, not evidence:
a disclosed report shows a bug was accepted somewhere, never that this target has it.
