# Case families and what each needs

These are review categories, not payload recipes or installed ledger case IDs.
Choose from observed topology, not server banners. Different routes can traverse
different parser pairs. Product/version, ALPN, `Via` and `Server` are hints;
none establishes a downgrade, a safe stack or an exploitable one.

| Family | Question | Required evidence beyond a symptom |
|---|---|---|
| CL.TE | Does a front-end use Content-Length where the upstream uses Transfer-Encoding? | Original and forwarded bytes plus attributed framing boundaries |
| TE.CL | Is the direction reversed? | Same evidence; never infer direction solely from a delay |
| TE.TE / field normalization | Do parsers recognize or normalize a framing field differently? | Repeated field occurrences and exact original/forwarded representation; ordinary dictionaries lose this |
| Duplicate/inconsistent lengths | Are ambiguous length declarations rejected or interpreted differently? | Actual occurrences and treatment at each hop; repeated equal lengths are not automatically exploitable |
| H2.CL / H2.TE | Does H2-to-H1 translation introduce an inconsistent length or illegal transfer coding? | Observed upstream H1 conversion and H2 stream/frame lengths; client-side H2 alone is insufficient |
| H2 field/request splitting | Does conversion serialize control data into a different request structure? | Input frame/field evidence and rewritten upstream bytes; separate syntactic acceptance from a completed extra request |
| CL.0 / 0.CL | Do participants disagree over consuming a declared body versus no body? | Identify which participant consumes which bytes; early response alone does not prove unread bytes persist |
| Client-side desync | Can a browser's own reused connection be desynchronized? | Owned browser delivery and connection reuse; Repeater success is not browser compatibility |
| Pause-based behavior | Does timeout/early response handling leave residual bytes? | Owner-observed lifecycle and matched non-pause/fixed control; no slow-connection/exhaustion exercise |
| Request tunnelling / response-queue misassociation | Does an extra upstream request or wrong response association occur? | Distinct per-hop request counts and response ownership; connection reuse is case-specific, not a universal prerequisite |
| h2c / protocol upgrade | Does an upgrade change the routing or trust boundary? | Explicit upgrade/route approval and observed protocol transition; no upgrade scanning or internal pivot |

## Controls and alternative explanations

- **Negative:** the same benign assertion on a fixed/strict parser path, corrected
  translation, or owner-isolated fresh-connection contrast appropriate to the
  hypothesis. Document the changed determinant; a different backend or arbitrary
  endpoint is not automatically a matched control.
- **Positive:** a well-formed benign sequence on the same intended route that
  establishes ordinary forwarding, marker capture and follow-up association work.
  It must not depend on desync or obtain private information.
- **Replay:** fresh inert markers and owner-verified clean state. Preserve failed
  attempts and denominators. Do not run until a chosen success threshold is met.
- **Confounders:** application echo, cache serving, WAF delay, throttling, upstream
  failure, retries, proxy normalization, early rejection, TCP segmentation and H2
  multiplexing. A connection diagram with guessed arrows does not eliminate them.

RFC 9112 defines transfer-coding precedence and connection/error handling, not a
claim that every message with both headers is exploitable. RFC 9113 defines H2
malformed-message and field rules; binary framing does not certify translation
implementations. Refer to the cited standards instead of maintaining an unverified
vendor-by-version exploitability matrix.
