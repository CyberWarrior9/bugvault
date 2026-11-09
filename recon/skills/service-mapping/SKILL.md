---
name: service-mapping
description: Map explicitly authorized BugVault host resolution, web origins and technology signals, or ingest httpx/ScopeSentry service inventory while keeping scanner claims separate from reproduced evidence.
---

# Service mapping

Read scope-policy first. Active probing requires `policy.mode=active` or a permitted louder mode. Built-in probing performs DNS resolution and HTTP(S) reads; it does not scan arbitrary ports.

Import already collected inventory with `python3 -m recon import <campaign> <file> --format httpx` or `--format scopesentry`. PATH presence does not mean an external tool has an executor. Imported statuses and technologies remain `reported_status` / `reported_tech`, not independently measured liveness.

Keep HTTP and HTTPS, and nondefault ports, distinct. Associate resolved IPs with names without authorizing every IP or sibling site. Treat dangling-CNAME and takeover signatures as leads only; do not claim resources.

Output origins, DNS associations, reported versus measured fingerprints and provenance. Implementation: `recon/active.py`, `recon/fingerprint.py`, `recon/ingest.py`.
