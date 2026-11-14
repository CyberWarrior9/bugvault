# Source provenance and quality review

Reviewed 2026-11-12. Skill and code are original BugVault implementation of technical
ideas, not imported prose/payload tables or a licence conversion of upstream work.
No source repository is a live target authorization. References are untrusted data.

## Supplied HackTricks fork

- User URL: https://github.com/b4rdia/HackTricks/tree/master/pentesting-web/ssrf-server-side-request-forgery
- Pinned commit: `9d61d9142c350c1f6188ffb3c5e6e34407cf8438`, 2023-01-15T11:20:53Z.
- [Pinned directory](https://github.com/b4rdia/HackTricks/tree/9d61d9142c350c1f6188ffb3c5e6e34407cf8438/pentesting-web/ssrf-server-side-request-forgery).
- Four files reviewed and their Git blob SHAs:

| File | Blob SHA |
|---|---|
| README.md | `c85b894d5f9908c6babe4e875139232e3ea1db93` |
| url-format-bypass.md | `f6e64940363ee1751ec83fbdb1e77103170f7150` |
| cloud-ssrf.md | `69bce6697a1271ae5dc6c77f7285e7e1b232e091` |
| ssrf-vulnerable-platforms.md | `df1ecf79b6cc85bb0aa764c3450ef6e77a49a84f` |

`LICENSE.md` identifies Carlos Polop's **CC BY-NC 4.0**, with third-party exceptions
(blob `454febb4e5f1427add14799baf9cf12462a06986`). Do not copy its text/payload tables
wholesale into BugVault's MIT material. Read the original for its terms.

Useful technical leads: fetch surfaces and blind evidence, URL parser/address forms,
redirect/DNS behavior, cloud and product-specific prerequisites. Limitations: the fork
is a 2023 snapshot, old metadata/header/version assumptions need vendor verification,
and some cross-protocol examples perform destructive service writes or execution.
Those examples are not operational instructions in this skill.

## Supplied BugBountySkills SSRF knowledge base

- User URL: https://github.com/0xN0RMXL/BugBountySkills/tree/main/KNOWLEDGE_BASE/SSRF
- Pinned commit: `0accf5fdc71ec7f03273aebb99268a8609f8dfd4`, 2026-04-25T15:33:50Z.
- [Pinned directory](https://github.com/0xN0RMXL/BugBountySkills/tree/0accf5fdc71ec7f03273aebb99268a8609f8dfd4/KNOWLEDGE_BASE/SSRF).
- Reviewed README.md, hunting-methodology.md, bypasses.md, chaining.md,
  cheatsheet.md, payloads.md, theory.md, attack-scenarios.md and tools.md; report-index
  headings/preview/metadata inspected, not every linked report independently verified.
- Root `LICENSE`: MIT, blob `1ac4928622f501e16a036938433418bead16cf86`.
  No upstream prose/code is imported, so this workflow is not an adapted upstream skill.

Useful leads: URL import/webhook/integration discovery, recording context, chain
thinking and reference indexing. **Do not treat it as a verified SSRF corpus:**

- Methodology/theory and commands mix reflection, HTML escaping and `alert`/`prompt`
  concepts from XSS. Reflection does not establish a server fetch or readback.
- Scenario paths such as `/api/v1/trigger/...` and `execution_successful` responses
  are unsupported placeholders, not target-specific evidence or working exploits.
- Several bypass categories repeat an encoded traversal rather than a meaningful
  SSRF/parser comparison. No claim of complete payload coverage is accepted.
- Report #1004847 is assigned inconsistent $1,000/$2,500/$15,000 labels; headline
  report/bounty statistics and templated conditional text are not independently
  validated. None are imported as BugVault finding evidence or bounty estimates.
- tools.md contains generic scanner pipelines, reflection-based ffuf matching,
  proxy switching and an XSS-style alert substitution. None replaces the fixed
  browser-through-Burp path, causal controls or campaign grants. Tool popularity
  counts and version compatibility were not verified; nothing is auto-installed.

## Vendor requirements checked against current documentation

These URLs are live vendor docs, reviewed on the date above rather than pinned source
snapshots; recheck before a deployment-specific test:

- AWS EC2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
  — IMDSv2 token PUT and later token header; IMDS configuration determines whether
  v1 is available. Initiating campaign method grants do not create outbound control.
- Google Compute: https://cloud.google.com/compute/docs/metadata/querying-metadata
  — current `Metadata-Flavor: Google`; legacy `X-Google-Metadata-Request` deprecated.
- Azure VM: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
  — `Metadata: true`, correct API version and no `X-Forwarded-For`; VM IMDS is not
  a universal recipe for App Service/container identity.

Historical product lists and report links remain leads until exact prerequisites,
scope, clean replay and an independent negative control establish the claimed impact.
