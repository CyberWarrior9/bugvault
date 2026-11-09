---
name: scope-policy
description: Review a BugVault campaign's written authorization, scope rules, exclusions, execution mode and request budgets before any authorized recon run or scope change.
---

# Scope and policy

1. Read the operator-supplied program rules and `scope.json`. Ask for missing authorization; a discovered hostname is not authorization.
2. Keep explicit URL schemes/ports/paths and exclusions. Bare hostname rules permit all ports, so prefer URL rules for narrow grants. Wildcards require an explicit program grant.
3. Run `python3 -m recon check <campaign> <url>` for intended URLs. Set passive/active/loud mode from program rules, not convenience.
4. Set `policy.max_rps`, `max_requests`, `max_seconds`. Runtime browsing requires separate `runtime.enabled=true` review.
5. Read `recon/README.md` limits: DNS-pinned connections and production egress isolation are not implemented. Do not represent these URL checks as a network sandbox.

Output the allowed scope, exclusions, mode and budgets; do not silently widen them. Implementation: `recon/campaign.py`, `recon/net.py`.
