# Sources and remediation

Reviewed 2026-11-20. Independently written BugVault instructions under the project
MIT license. These links support protocol concepts, not current target findings.
No external exploit payloads, scripts, scanner code or substantial teaching text
are vendored. No local upstream skill snapshot or vendor matrix is claimed verified.

## Primary references consulted

- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3),
  with §§5.1, 6.1, 6.2 and 11.2: HTTP/1.1 field parsing, framing precedence,
  invalid lengths, ambiguous-message forwarding and request-smuggling risks.
- [RFC 9113 §§8.1.1–8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1.1):
  malformed HTTP/2 messages, content-length/DATA consistency, field validity and
  prohibited connection-specific fields. The `TE: trailers` exception is not
  permission for HTTP/1 `Transfer-Encoding` in H2.
- [PortSwigger Web Security Academy: request smuggling](https://portswigger.net/web-security/request-smuggling):
  parser disagreement, CL.TE/TE.CL/TE.TE, downgrade, browser/pause-based families,
  request tunnelling, limitations of disabling reuse and mitigation guidance.
  Use its linked family-specific material for further authorized study. A training
  lab or a research article does not establish a live site's configuration.

The existing `plans/http-request-smuggling.md` is a separate, modified design
document and is not this skill's implementation contract. This slice adds no raw
transport, grants, payload generation, target scanner or smuggling ledger.

## Defensive recommendations

- Reject ambiguous or invalid framing and fields at every relevant hop. Where
  normalization/forwarding is required, apply the standards consistently; do not
  forward conflicting framing unchanged. Fail closed and manage affected
  connection state rather than reuse a partially consumed request.
- Avoid unnecessary H2-to-H1 conversion. If translation remains, validate the
  rewritten message and lengths; client-facing H2 alone proves nothing about the
  upstream implementation. End-to-end H2 removes classic H1 framing ambiguity,
  not all parser, routing or application implementation bugs.
- Consume request bodies correctly or close connections safely on early errors.
  Separate pools where appropriate. Disabling reuse can mitigate some variants,
  but is not a complete fix for request tunnelling or every desync family.
- Update supported proxy/server components, then repeat the exact regression with
  matched controls and owner traces in isolation. A version/banner table or WAF
  signature is not a substitute for verifying the actual route and framing fix.
