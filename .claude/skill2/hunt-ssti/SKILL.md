---
name: hunt-ssti
description: "Use for every BugVault ssti coverage row or whenever an input may be rendered by a server-side template in a response, later page, email or export. Inventory the exact field and render surface, use recon ssti's offline arithmetic probes and raw-capture trace, distinguish client-side rendering and shared syntax from confirmed server-side evaluation, then hand evidence to the validator. Do not infer RCE or a unique engine from an expression result."
license: "MIT; original BugVault workflow. No external payload text imported."
metadata:
  implementation: "recon/ssti.py offline probe and evidence ledger"
  reviewed: "2026-11-14"
---

# Hunt: server-side template evaluation

An input is not a finding because it contains braces, appears on a template path,
or makes an error page. Treat the unit of work as **one field context × one actual
render surface**. A submission response, a later role's view, an email, an export
and an async render are independent; a negative on one does not close another.

## Workflow

1. Read `scope-policy` and the campaign's written rules. Use only supplied test
   accounts and the dedicated browser through Burp, or a recorded campaign
   execution path. Do not test a staff mailbox without the program's allowance.
   `recon ssti` itself is offline and sends nothing.
2. Import capture(s), run `python3 -m recon fields sync <campaign> --asset-id N`,
   and inspect `python3 -m recon fields show <campaign> --asset-id N --case ssti-eval`.
   The method, location, field and account must match the real workflow.
3. Create/reuse a set with `python3 -m recon ssti probes <campaign> --asset-id N
    --field FIELD --method POST --location json --account TEST --role ROLE
    --tenant TENANT --workflow STATE` when those labels match the capture.
    Save the set ID. Different captured contexts get different probe sets.
   Generated expressions only multiply bounded integers; the separate control
   is ordinary literal text. Submit each probe independently on the disposable
   test field, preserving a request capture that contains the exact probe.
4. Record later sinks separately: `python3 -m recon ssti surface <campaign> --set
   SET --kind email --label 'test mailbox notification'`. Use `export`, `view`,
   `async` or `dom` as appropriate. Do not label a synthetic or client-only
   render as a server response.
5. Import actual response captures or save a campaign-local artifact, then
   `python3 -m recon ssti trace <campaign> --surface SURFACE --probe braces-a
   --response ID` (or `--artifact evidence/message.eml`). Repeat for both
   arithmetic variants and the literal control on that **same** surface.
   `python3 -m recon ssti status <campaign> --set SET` and `plan` show gaps.
6. `python3 -m recon ssti record <campaign> --surface SURFACE --case confirm
   --state observed --note 'Two raw evaluations and literal control, with receipts'`
   refuses an incomplete proof. `fingerprint` lists *syntax families*, not a
   unique engine or version. `verify` checks hashes and reclassifies captures.
   Consult [references/evidence.md](references/evidence.md) before an impact
   claim. A `severity-gate` event records low/medium after confirmation, or
   high/critical only after the matching depth rung is observed; it promotes no
   finding.

## Depth rungs (grant-gated, offline)

After confirmation, read `ssti.depth_grants` in `scope.json` (copied from the
program's written rules). `recon ssti plan` prints the gates, attempt markers,
listed data paths and read-only methods. The ledger records **operator-supplied
evidence**; it does not read a file, use a token, resolve a callback host or send
a request. Any live action happens separately in the dedicated browser through
Burp (or the recorded campaign execution path), then the artifacts are supplied.

- `cred-read` (`file-read`): listed path only, two distinct artifacts (evidence
  and control), a redaction marker, no secret signature. Raises the ceiling to
  high.
- `token-use` (`execution`): after observed `cred-read`; one read-only
  `GET`/`HEAD`/`OPTIONS` exercise on one in-scope plain URL carrying the set's
  marker and no credential-named query parameters; one attempt; redacted
  artifact. Raises the ceiling to critical.
- `lateral` (`execution`): after observed `token-use`; approved
  `ssti.callback_hosts` (or `ssrf.callback_hosts`) receiver, different from the
  render origin, carrying the marker; one OOB attempt; artifact contains the
  marker. Raises the ceiling to critical.

```bash
python3 -m recon ssti record <campaign> --surface N --case cred-read --state observed \
  --grant file-read --target .env --attempts 1 \
  --artifact evidence/env-redacted.txt --artifact evidence/env-control.txt --note '...'
python3 -m recon ssti record <campaign> --surface N --case token-use --state observed \
  --grant execution --exercise GET --attempts 1 --target 'https://app/...?marker=...' \
  --artifact evidence/token-response-redacted.txt --note '...'
python3 -m recon ssti record <campaign> --surface N --case lateral --state observed \
  --grant execution --target '<marker>.callbacks.example' --attempts 1 \
  --artifact evidence/oob.txt --note '...'
```

`verify` re-hashes depth artifacts; `status` withdraws the raised ceiling if any
artifact changed. A grant or artifact is not impact proof: the validator still
checks provenance, causality, the owner of the exercised token, and the realism
gate. Never store a live credential or token value; redact it before recording.

## Interpretation and limits

- A DOM-only result belongs with `hunt-xss`; an HTTP error/status alone proves
  no template evaluation. An absent marker, incomplete response, or unobserved
  email/export is inconclusive. A negative requires all six probes to remain
  literal in complete captures with submission receipts on that surface.
- An arithmetic result does not establish file access, sandbox escape, command
  execution, credential access, severity, or attacker reachability. Depth events
  are operator-supplied evidence under a grant; they can raise the ceiling but
  this module does not read a file, use a token, send a request or move laterally.
  No engine identification, escape generator, native execution or automated
  finding promotion is implemented here. Use the existing validator and realism
  gate for any claim beyond evaluation; never elevate a lead from a syntax match.
- Respect rate/budget limits, avoid destructive statements and other users'
  data, and restore the supplied test field after stored probes. A broken mail
  pipeline is not an impact proof.
