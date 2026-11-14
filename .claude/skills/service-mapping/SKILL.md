---
name: service-mapping
description: Map explicitly authorized BugVault host resolution, web origins and technology signals, or ingest httpx/ScopeSentry service inventory while keeping scanner claims separate from reproduced evidence.
---

# Service mapping

Read scope-policy first. Active probing requires `policy.mode=active` or a permitted louder mode. Built-in probing performs DNS resolution and HTTP(S) reads; it does not scan arbitrary ports.

Import already collected inventory with `python3 -m recon import <campaign> <file> --format httpx` or `--format scopesentry`. PATH presence does not mean an external tool has an executor. Imported statuses and technologies remain `reported_status` / `reported_tech`, not independently measured liveness.

Keep HTTP and HTTPS, and nondefault ports, distinct. Associate resolved IPs with names without authorizing every IP or sibling site. Treat dangling-CNAME and takeover signatures as leads only; do not claim resources.

## Hunting subdomain takeover deeper

Takeover detection has two code paths: a dangling CNAME with no A record (named by
provider via `takeover_providers_for_cname`), and a live body matching an unclaimed-
service signature. `dig` in PATH is required — without it, unresolved hosts record a
`collection-gap` fact instead of a takeover check.

Takeover windows are **temporal**: they open when the target deletes their Heroku app
or lets a domain lapse, not when you first probe. Re-run `probe` on takeover-lead
hosts periodically and on every re-engagement; a lead that was dead last month may be
claimable now.

The imported BugBountySkills index contains 165 source-tagged pointers, not verified
severity statistics. Do not infer severity or payout from its generated labels.
When a `takeover-lead` fires, `probe` scans stored responses for parent-domain cookie
strings (`takeover-impact-context` facts). These are heuristic context hints, not
proof of a session cookie or session theft. OAuth redirect allowlists and CSP entries
are likewise chain hypotheses: cookie attributes, token validation and browser
policy can prevent the proposed impact. Verify any permitted chain on test accounts.
Report demonstrated standalone impact at its honest severity; if impact depends on
an uncompleted chain, park it with evidence until that chain is proven.

Output origins, DNS associations, reported versus measured fingerprints and provenance. Implementation: `recon/active.py`, `recon/fingerprint.py`, `recon/ingest.py`.
