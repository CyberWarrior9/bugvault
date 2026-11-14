# hunt-csrf sources, selections and corrections

Retrieved and reviewed 2026-11-13. `hunt-csrf`, its case catalogue and `recon/csrf.py`
are **independently written** for BugVault (MIT). The sources below supplied ideas;
no prose, tables, images or code were copied from them.

## Pinned sources

| Source | Identity | Licence | Selected | Not imported |
|---|---|---|---|---|
| HackTricks fork `b4rdia/HackTricks`, `pentesting-web/csrf-cross-site-request-forgery.md` | branch snapshot `9d61d9142c350c1f6188ffb3c5e6e34407cf8438` (2023-01-15); last change to the page `1d1f2554c96d0ae01edfa5d45d6af25199669f97` (2023-01-13) | CC BY-NC 4.0 (Carlos Polop) | ideas: complete token omission and substitution, cross-session token reuse, cookie-paired tokens needing a planting primitive, POST-to-GET and override parameters, content-type changes, Referer omission and weak matching | all wording, tables, images and example code (non-commercial licence; several examples are broken or browser-impossible); Flash/ActiveX delivery; the login brute-force script; the flowchart's "not possible" end states |
| mind-hunt `skills/hunt-csrf/SKILL.md` (local copy; README attributes `MindflareX/mind-hunt`, no upstream commit resolvable) | SHA-256 `2f224f4c364183f67442e2bc6c07660adff0e481dd038c135f077a50f5c7d660`; licence file SHA-256 `c2e7412e139a1904d1cd23810f1fba124eeb6933780c1f8fc1fd03c356195aca` | MIT, Copyright (c) 2026 MindflareX | ideas: crown-jewel action ranking, account association and social linking, sibling-origin delivery, GraphQL GET mutations, middleware/path mismatches, BFF constant headers and SignalR carve-outs, chain handoffs to ATO | its report counts and payout figures (unverified), the referenced CSRF templates (absent from its arsenal), and the verdicts corrected below |
| BugBountySkills `KNOWLEDGE_BASE/CSRF/` (10 files) | commit `0accf5fdc71ec7f03273aebb99268a8609f8dfd4` (2026-04-25) | MIT, Copyright (c) 2026 0xN0RMXL | `reports-index.md` as a lead list; checked leads: GitLab #1122408 (GraphQL mutations over GET), WakaTime #675398 (a second token channel masks omission), Nextcloud #1878381 / GHSA-52hv-xw32-wf7f (OIDC state disclosed on an error path), LINE #2473862 (client-side path traversal), Stripo #915541 (WebSocket handshake + sensitive messages) | generic payload/bypass templates that describe injection rather than CSRF; severity, bounty, quality and frequency figures |

Browser and protocol behaviour comes from primary references: OWASP CSRF Prevention
Cheat Sheet (synchronizer tokens, custom headers, origin checks, client-side CSRF, Fetch
Metadata), MDN (Set-Cookie, Site, CORS, forbidden request headers), RFC 9700 §4.7, the
Django CSRF documentation, Duende BFF documentation, Microsoft SignalR security
documentation and the OWASP WebSocket and SAML cheat sheets.

## Corrections carried into the workflow and the engine

| Source claim | What BugVault does instead |
|---|---|
| A token that stays the same across page loads of one session is a bug | per-session synchronizer tokens are a valid design; `token-context` tests cross-session, cross-account and lifecycle transitions |
| A cookie without SameSite is "vulnerable" | omitted SameSite is browser-default behaviour, different from explicit Lax, and build-dependent; `cookie-delivery/default-lax-age` records the observed behaviour |
| Removing the token and getting HTTP 200 proves CSRF | the engine compares independent before/after readbacks; one removed channel may leave another validating (`omit-all-channels`) |
| A WebSocket 101 proves cross-site WebSocket hijacking | 101 only switches protocols; `realtime-authority` observations need the protected message exchange |
| A constant `X-CSRF: 1` header is a broken token | an enforced constant header with restrictive CORS is a real defense; `bff-protection` looks for exclusions and permissive preflight |
| Missing OAuth `state` / an open RelayState redirect is CSRF | transaction binding (state, PKCE, nonce, InResponseTo) is assessed together; redirect allowlisting is a separate question |
| Any sibling subdomain defeats SameSite | a same-site initiator needs actual control of that origin, recorded as a prerequisite |
| A proxy-forged Origin header shows browser behaviour | replays carry initiator `none`; only browser attempts can be observed CSRF |
| `ACAO: *` makes credentialed reads possible | wildcard origins never allow credentialed reads; response readability and request delivery are recorded separately |

## Licence notices

The MIT-licensed sources require their copyright and permission notice only where
substantial portions are reproduced. None are reproduced here; the notices are cited
for attribution:

- mind-hunt — MIT License, Copyright (c) 2026 MindflareX.
- BugBountySkills — MIT License, Copyright (c) 2026 0xN0RMXL.
- HackTricks fork — Creative Commons Attribution-NonCommercial 4.0, Carlos Polop; used
  for ideas only.
