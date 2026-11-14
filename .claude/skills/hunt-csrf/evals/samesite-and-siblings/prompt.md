---
tags: [skill-creator]
max_turns: 20
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

Text-only exercise for an authorized BugVault campaign (placeholder hosts). On
https://app.acme-lab.example the session cookie is `sid=...; Path=/; HttpOnly; Secure;
SameSite=Lax` (host-only). POST /account/email has no anti-CSRF token. Recon also found
https://blog.acme-lab.example, a marketing site run by a third party that we do not
control. One teammate says Lax makes CSRF impossible here; another says the blog
subdomain breaks SameSite so the bug is critical. Give the CSRF plan for this action:
what to test, in what order, from which origins, and what each outcome would mean. No
live requests.
