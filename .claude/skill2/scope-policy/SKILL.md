---
name: scope-policy
description: Review a BugVault campaign's written authorization, scope rules, exclusions, execution mode and request budgets before any authorized recon run or scope change.
---

# Scope and policy

1. Read the operator-supplied program rules and `scope.json`. Ask for missing authorization; a discovered hostname is not authorization.
2. Keep explicit URL schemes/ports/paths and exclusions. Bare hostname rules permit all ports, so prefer URL rules for narrow grants. Wildcards require an explicit program grant.
3. Run `python3 -m recon check <campaign> <url>` for intended URLs. Set passive/active/loud mode from program rules, not convenience.
4. Set `policy.max_rps`, `max_requests`, `max_seconds`. Runtime browsing requires separate `runtime.enabled=true` review.
5. Read `recon/README.md` limits: built-in HTTP uses DNS/IP validation and pinned connections, but shells/scanners/DNS utilities are not OS-egress sandboxed. Configured proxies fail closed. Private DNS requires explicit allowed ranges; deny ranges win. Do not present a client boundary as a process-wide sandbox.
6. Grant only permitted methods. Full active-testing set (when authorized):
   `"allowed_methods": ["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"]`
   under `policy`, with `"mode": "active"` or `"loud"`. Defaults stay GET/HEAD;
   passive mode cannot grant the extra methods. An OPTIONS response's `Allow` header
   is not authorization to use those methods. PUT/DELETE act only on disposable
   operator-owned resources with cleanup agreed in advance.
7. Permit state-changing tests and operator-run scanners through a standing campaign
   execution plan when the program's written rules allow them, not blanket bans.
   Record the permission and its source in `scope.json`'s `rules`; keep the detailed
   run plan and evidence in the campaign's private `.recon/`. For writes, name the
   disposable test resources, allowed operations, before/after checks and cleanup.
   For scanners, name the tool/version, exact targets and exclusions, enabled checks,
   methods, rate, concurrency, request cap, time window and stop conditions. Restrict
   methods to `policy.allowed_methods` and account for all external traffic against
   the campaign budgets using `references/burp-workflow.md`. Stop on 429, lockout,
   CAPTCHA, unexpected side effects or the recorded cap; do not evade these controls.
   Keep the browser/Burp path as the default; an approved plan can separately permit
   native requests or operator-run scanners. Do not repeatedly request exceptions
   for actions already within the plan; tool approval prompts still apply. No grant
   is implied by a missing browser, a failed policy check or an installed binary.
   These grants are operator-reviewed instructions, not a machine-enforced scanner
   policy: recon has no external scanner executor or scope/rate/budget adapter.

For a new campaign, grant methods explicitly (this writes config, sends no requests):

```bash
python3 -m recon init <campaign> --seed https://app.example.com --mode active \
  --allow-method POST --allow-method PUT --allow-method PATCH \
  --allow-method OPTIONS --allow-method DELETE
```

For OTP races or out-of-band callbacks, read
`references/burp-workflow.md` in this skill. It distinguishes Repeater/Intruder from
Collaborator, defines an operator-only evidence handoff, and records the integration
plan. Burp MCP is registered project-wide for all tool-capable model selections and
can supply bounded history/evidence reads. **No campaign-enforced Burp executor is
implemented.** A method grant does not authorize active MCP actions or bypass a
failed scope/rate/budget check; generated briefs do not grant external execution.

For interactive login/logout/signup, test mailboxes or browser-based target tests,
read `references/browser-workflow.md`. Use only the dedicated visible profile under
BugVault and its Burp proxy after browser-control, routing and HTTPS trust are verified.
Preparation alone does not establish browser control; personal profiles stay untouched.

Output the allowed scope, exclusions, mode, budgets and any standing write/scanner
permissions; do not silently widen them. Implementation: `recon/campaign.py`, `recon/net.py`.
