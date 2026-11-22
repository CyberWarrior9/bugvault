# Validator/fetcher comparison matrix

Only after permission and a baseline. Use reserved-domain examples for explanation,
not as actual recipients. Substitute approved controlled infrastructure and inspect
its logs. Test one representation change per attempt, not a huge payload list.

| Case ID | Controlled comparison | Evidence and boundary |
|---|---|---|
| `parser-authority` | Scheme/authority separators, userinfo, explicit port, fragment, backslash handling, repeated fields | Record what the validator accepted and which host the fetcher contacted; a string containing an allowed name does not prove that name was the destination |
| `parser-encoding` | Percent-encoding at the actual decoding layer; case/trailing dot; Unicode and IDNA normalization | Compare canonical baseline, rejected control and final destination. Avoid assuming double decoding or copying one parser's result to another |
| `ip-representation` | Canonical vs numeric/short/hex/octal/mixed IPv4, IPv6 compressed/expanded and IPv4-mapped forms | Only an approved owned receiver address, or offline parser tests. Browser/server/library support differs. Private/loopback/link-local scope is a separate grant |
| `path-extension` | Allowlisted path/extension vs trailing separators, encoding, query/fragment and normalization | Same approved destination and non-sensitive resource; extension acceptance alone is not an unauthorized read |
| `redirect-hop` | Approved receiver A returns one redirect to approved receiver B; then a short bounded multi-hop chain if needed | Keep Location values, per-hop logs and final response. Verify every hop is revalidated, not just the first URL. No infinite loops or redirects to unapproved destinations |
| `redirect-method` | Observe method/body behavior for the redirect types supported by this fetcher; separately inspect cross-origin and HTTP/HTTPS handling | 301/302/303 handling can differ from 307/308. Record actual behavior, never assume preserved methods. Forward only synthetic credentials to owned receivers |
| `dns-cname` | Owned name/CNAME and controlled A/AAAA answer sets | Record answer sets, validation/connect timing and actual peer where instrumentation permits. A DNS resolver log is not a socket connection or read |
| `dns-rebinding` | Separately approved owned DNS changes between validation and connection, with an exact canary destination | Cap resolution changes, attempts, time and callbacks; no public rebinding service. Mark blocked when routing/TTL/timing cannot be measured through approved tools |

For a suffix/substring allowlist, use controlled names on both sides of the comparison;
do not use another organization's live hostname as infrastructure. CNAME traversal and
mixed A/AAAA results must all stay within approved destination rules. Do not let a URL
that appears public silently resolve to an internal address without the internal grant.

Check scheme, host, port and path together; credentials in URL authority are not a safe
substitute for application authentication. Rejecting one representation gives a narrow
negative result only. A parser discrepancy matters when it causes a request across the
intended boundary; it does not by itself establish data access or impact.

## Distinguish blocks from uncertainty

- Input rejected with no callback and a healthy positive control: narrow negative
  for this input/trigger/window; still document any async/cache uncertainty.
- Accepted input, DNS only: resolution observed, HTTP fetch unproven.
- HTTP callback, uncertain origin: unattributed interaction, not confirmed SSRF.
- Known outbound fetch but no readable body: blind primitive; don't claim metadata
  exfiltration without a permitted return path and artifact.
- No connected browser, unsupported arbitrary TLS/SNI, missing DNS permission or
  unknown recipient: blocked, not evidence that a bypass failed.

Remediation checks in an owned fixed lab should compare normalized URL policy with
the addresses used for the connection and recheck every redirect. Application egress
and credential minimization provide defense in depth; the recon client's pinned egress
does not secure the tested application's own outbound fetcher.
