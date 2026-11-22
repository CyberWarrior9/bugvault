# SSTI evidence boundary

`recon ssti` keeps one random seed per asset/method/location/field/account/role/
tenant/workflow. Role, tenant and workflow must match an observation for that
field and location. The coarser field ledger still collapses those variants;
consult the SSTI report's missing-context rows before claiming coverage.
Each expression has distinct opening and closing markers; its result must occur
**between those markers in raw server-side bytes**, not only in the DOM. Two
different arithmetic operands and a separate literal control must appear on the
same surface, with stored request receipts carrying the exact probes.
For a submission response, the receipt is that response's own request. A later
stored response requires an earlier matching submission; an export response may
be delivered by the submission itself. Artifact creation time and the account/
role actually owning a response cannot be proved by a marker match or the receipt
alone: mismatched labels on imported submissions are rejected, but unlabelled
captures still require independent provenance and causal-path review.

`braces` syntax is shared across several engines; `dollar` syntax is also
ambiguous. Neither family identifies an engine, its sandbox, its version, or an
escape path. A `confirmed_families` entry means only the above evaluation
standard was met. The operator still checks the capture's provenance and the
program's authorization before reporting.

Artifacts must be regular files within the campaign directory, at most 5 MB.
Only their paths and hashes are stored in the SSTI ledger; `verify` re-reads them.
The trace does not HTML-entity-decode output, parse compressed PDF streams or
decode MIME parts; supply a
separately captured raw text render when possible. Never infer a negative from
an unparsed artifact. A stale or tampered reference invalidates its evidence.

Depth evidence (`cred-read`, `token-use`, `lateral`) is copied by SHA-256 into
`.recon/ssti-evidence/` and is also offline. `cred-read` requires the `file-read`
grant, a listed data path, a confirmed surface, two distinct artifacts, a
redaction marker and no obvious secret signature. `token-use` requires the
`execution` grant, a prior observed `cred-read`, one read-only `GET`/`HEAD`/
`OPTIONS` exercise on an in-scope plain URL carrying the set's marker and no
credential-named query parameters, one attempt and a redacted artifact. `lateral` requires a prior observed `token-use`,
an approved callback host different from the render origin and carrying the
marker, one attempt, and an OOB artifact containing the marker. Grants are
campaign config copied from the program's written rules; `ssti.callback_hosts`
falls back to `ssrf.callback_hosts`. Depth artifacts do not prove that the
tool read a file, used a token or moved laterally: the operator performed the
action separately and the validator must inspect provenance, token ownership and
the realism gate. Never record a live credential or token value.
