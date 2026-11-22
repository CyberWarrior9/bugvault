---
name: hunt-csrf
description: "CSRF hunting for authorized BugVault campaigns, organized per state-changing action instead of per field: a host-specific action inventory from captures, forms, JS and specs (fieldless actions, GET mutations, GraphQL operations and realtime handshakes included), the offline action x context x case ledger (recon csrf), and fifteen case families covering token channels and binding, double-submit pairs, Origin/Referer/Fetch Metadata, SameSite cookie delivery by site relationship, body representation and preflight, method/route/middleware coverage, GraphQL transport, client-side CSRF, login/linking/SAML transactions, WebSocket/SignalR and BFF header defenses, with browser-initiated exercises and chain handoffs to account takeover. Use for every coverage row of class csrf and whenever an action changes account, security, value or admin state."
license: "MIT; original BugVault workflow. Concepts selected from a 2023 HackTricks fork (CC BY-NC 4.0, ideas only, no text), mind-hunt hunt-csrf (MIT) and BugBountySkills (MIT); pinned sources and corrections in references/sources.md"
metadata:
  implementation: "recon/csrf.py action ledger (csrf sync/plan/record/status/verify); recon/csrfmeta.py capture metadata; recon/score.py csrf seeding"
  reviewed: "2026-11-13"
---

# Hunt: CSRF

CSRF lives in **actions**, not fields. A logout-everywhere button, a GET link that
deletes, a GraphQL mutation behind one `/graphql` path and a WebSocket hub method
are each separate actions, and a protected form proves nothing about its siblings
on another host, method, MIME, role or workflow. This skill turns every
state-changing action into explicit per-origin work and drives each one through the
case families that apply to it, from a real browser initiator.

## When this skill applies

- `coverage.md` shows a row of class `csrf`. `recon/score.py` seeds it for
  POST/PUT/PATCH/DELETE, for GET or method-unknown routes carrying a state-change
  verb (`/items/7/delete`, `/unsubscribe`) or an action selector (`?action=`,
  `?op=`), and for `ws`/`wss` endpoints.
- Any action that changes **identity** (email, password, MFA, recovery, linked
  identities), **security** (API keys, webhooks, roles, invites, sharing),
  **value** (billing, transfers, orders) or **admin** state.
- Login, link/connect, OAuth/OIDC and SAML callbacks; GraphQL mutations;
  WebSocket/SignalR/Socket.IO hubs; backend-for-frontend APIs.

## Setup

1. Read `scope-policy`. Confirm `csrf` is not in `excluded_bug_classes`. The victim
   browser sends each action with its own method, so that method must be granted in
   `policy.allowed_methods`. Live work runs in the dedicated browser through Burp,
   or through a path the campaign execution plan records.
2. Two supplied test accounts: **V** (victim, signed in to the dedicated browser)
   and **A** (attacker). Every exercised change lands on V's own disposable data;
   restore it afterwards (`effect-handoff` / `state-restore`).
3. Initiator origins, written into the campaign notes: a **cross-site** origin you
   control for attacker pages, and a **same-site sibling** only when the campaign
   has one you legitimately control (an owned or program-supplied host, or a
   confirmed takeover/XSS finding). Discovering a sibling hostname does not make it
   yours.
4. Build the ledger: `python3 -m recon csrf sync <campaign>`. Sync is idempotent and
   sends nothing; `plan` and `status` re-run it.

## Step 1 — the action inventory (where)

Every `scheme://host:port` is its own origin and its own inventory. Give each
origin a role: application, API, admin/dashboard, auth callback, integration/BFF,
realtime. `python3 -m recon csrf status <campaign>` prints per origin the captured
versus declared-only actions, open cases, contexts waiting for a capture or a
credential confirmation, and stale cases.

The ledger reconciles actions from every source recon already has: HAR/Burp
captures (per account, role, tenant and workflow), forms (method, enctype, token
field names), JS endpoints and lazy chunks, sourcemaps, OpenAPI operations
(request content types and security schemes), GraphQL operation names from client
code and `ws`/`wss` endpoints. Version siblings are not separate actions; they are
the `legacy-version` variant of the action they shadow.

Work highest value first: identity, then security, then value, then admin, then
other writes. Hunt for the actions crawls miss:

- settings pages with several forms, each its own action;
- bulk / approve / delete / restore / archive and their undo actions;
- link, unlink, connect, import, invite, transfer-ownership flows;
- API-key, token, webhook and integration management;
- GET links that act (`/unsubscribe?u=`, `/confirm`, `?action=delete`);
- fieldless buttons (logout everywhere, regenerate key, resend, leave team);
- legacy `/v1/` routes and secondary dashboards on their own subdomains;
- GraphQL mutations named in client bundles but never seen in traffic;
- realtime hub methods that change state.

## Step 2 — capture each action (when)

Authenticated actions need L4 capture. Walk every workflow as V (and as A for
comparisons) in the dedicated browser, export one HAR/Burp file per account, role,
tenant and workflow, and import it with `python3 -m recon import-har` or
`python3 -m recon import-burp`. Imports keep value-free CSRF metadata per capture:
request MIME, the authority mechanism (cookie, browser-managed Authorization such as
Basic/NTLM, or an explicitly attached header), anti-CSRF token channel names,
custom-header flags, Origin/Referer origins, Sec-Fetch values, Set-Cookie names
with SameSite/Domain/Path/Secure/HttpOnly, and GraphQL operation type and name (so a
captured `mutation updateEmail` attaches to its own action; documents and variables
are never kept). `python3 -m recon import-openapi` adds
declared operations with their request types and security schemes.

- A declared-only action (form/JS/spec, no capture) is `waiting-capture`; capturing
  it supersedes the declared context.
- A context whose capture shows no credential (sanitized HAR exports drop Cookie and
  Set-Cookie) is `needs-confirmation`: check DevTools for the cookie instead of
  assuming the action is unauthenticated.
- Each new account, role, tenant, workflow, MIME or authority mechanism is a new
  context with its own cases.

## Step 3 — baseline every context

`python3 -m recon csrf plan <campaign> --action <id>` lists the action's contexts and
their case cards. Every attack case waits on the baseline:

- the legitimate request exactly as the app sends it (method, MIME, every token
  channel, which credentials ride along);
- an independent **state readback** before and after (profile page, API GET, the
  linked-identity list): this is what every later case compares against;
- the delivery mode the app uses (form, navigation, fetch/XHR, WebSocket message).

```bash
python3 -m recon csrf record <campaign> --context 12 --case baseline --state observed \
  --artifact before=evidence/csrf/12-before.json --artifact after=evidence/csrf/12-after.json \
  --artifact request=evidence/csrf/12-legit-request.txt --browser "Chrome 131 stable"
```

If the baseline shows the action changes nothing (a read-only POST, a search),
record the baseline `n-a` with the reason; its other cases drop out of open work.

## Step 4 — work the case families (how deep)

The plan shows, per context, which families apply (and the reason when one does
not), each card's readiness and its open variants. Work `ready` cards top-down.
Each variant is its own attempt, recorded with `--variant`; a case-level `negative`
is accepted once every applicable variant is recorded. The full variant list with
techniques is [references/cases.md](references/cases.md).

| Family | Applies when | What to exercise |
|---|---|---|
| `baseline` | always | legitimate request, independent readback, delivery mode |
| `token-enforcement` | ambient credential | remove the token from every channel at once, empty value, invalid same-format value, another accepted channel, duplicate-parameter precedence |
| `token-context` | a token channel was captured | token from another session and from account A; across logout/login, renewal, expiry; leak surfaces (URL, Referer, cached and error pages, JS-readable endpoints) |
| `cookie-binding` | a CSRF-named cookie pairs with the token | pairing design (naive, signed, session-bound), mismatched pairs, planting a pair through an established cookie-setting primitive |
| `origin-metadata` | ambient credential | browser-emitted cross-site Origin, suppressed Referer, null origin, lookalike registrable domains, trusted siblings, Sec-Fetch enforcement and its fallback, redirect hops |
| `cookie-delivery` | ambient credential | top-level GET, top-level POST, subresource/frame, credentialed fetch, same-site sibling, SameSite-omitted fresh versus aged, POST-to-GET redirects |
| `representation` | the action carries a body | urlencoded, multipart and text/plain encodings the parser accepts, MIME-parameter leniency, preflight versus the actual request |
| `middleware-coverage` | ambient credential | the action over GET, `_method` override parameters, path normalization variants, legacy versions, middleware-exempt prefixes |
| `graphql-operation` | GraphQL endpoint | the mutation over GET, simple-body transports, batching/aliases, persisted queries — per operation |
| `client-input-request` | JS client / SPA | URL, hash, postMessage or path input steering the app's own authenticated request builder |
| `identity-transaction` | login/link/OAuth route | login CSRF, link-callback swap, state + PKCE + nonce bound to the browser session, error-path disclosure |
| `saml-transaction` | SAML route | unsolicited responses, InResponseTo binding, RelayState as state, replay |
| `realtime-authority` | WebSocket/SignalR | handshake Origin check, cookie-authenticated connection, a protected message executed, fallback transports |
| `bff-protection` | constant custom header or `/bff` | header enforcement with restrictive CORS, excluded routes and hubs, permissive preflight, widened cookie Domain |
| `effect-handoff` | an attack case is observed | carry the demonstrated change into its chain, then restore V's state |

## Step 5 — exercise from the browser and record

- Host the initiator page on the recorded origin and open it in V's dedicated
  browser session: the browser builds the request. DevTools shows whether the
  cookie attached, which Origin/Referer/Sec-Fetch headers went out and the
  preflight decision.
- Use Burp Repeater for server questions (which channel the validator reads,
  whether text/plain still parses, which duplicate wins) and record them as
  `--attempt-kind replay --initiator none`. A forged Origin or Cookie header in
  Repeater shows the server's policy, not what a browser sends.
- Read the state back independently afterwards: the forged request's response may
  be a 200 error page, a 204, a redirect, or unreadable under CORS while the write
  still happened.
- Record each variant with its browser facts:

```bash
python3 -m recon csrf record <campaign> --context 12 --case cookie-delivery \
  --variant top-level-post --state observed --initiator cross-site \
  --initiator-origin https://attacker-lab.example --delivery form-post \
  --browser "Chrome 131 stable" --tool-ref burp-history:5521 --requests 1 \
  --artifact before=evidence/csrf/12-before.json --artifact after=evidence/csrf/12-after.json \
  --artifact request=evidence/csrf/12-cross-site-request.txt \
  --artifact initiator-page=evidence/csrf/12-poc.html
```

- A same-site initiator carries `--prerequisite` naming how that sibling origin is
  controlled (owned lab host, finding id, program-supplied host).
- Realtime cases attach the protected exchange as `--artifact messages=...`.
- Burp item numbers go in `--tool-ref`; they stay external references.
- `python3 -m recon csrf verify <campaign>` re-hashes every recorded artifact.

## Defense map

| Defense seen | How to work it |
|---|---|
| Synchronizer token | every channel at once, empty, invalid, another session, account A, logout/login, leak surfaces; a stable per-session token is a normal design, so test transitions rather than stability |
| Double-submit cookie | pairing design, mismatched pairs, planting through an established cookie-setting primitive while V keeps V's own session |
| `SameSite=Lax` | does the action accept GET (`get-mutation`, then top-level navigation)? POST-to-GET redirects, a controlled same-site sibling, Domain-widened cookies |
| `SameSite=Strict` | same-site siblings still send it; shared cookie Domains |
| SameSite omitted | the browser default is not the same as explicit Lax; record fresh versus aged behaviour on the recorded build |
| `SameSite=None` | cross-site forms, frames and credentialed fetch all carry it; measure attachment |
| Origin / Referer check | null origin from a sandboxed frame, suppressed Referer, lookalike registrable domains against prefix/suffix/substring allowlists, trusted siblings, redirect hops, missing-header fallback |
| Fetch Metadata | `Sec-Fetch-Site` enforcement and the fallback when the header is absent (plain-HTTP origins do not send it) |
| JSON-only body | text/plain, urlencoded and multipart encodings the parser still accepts; MIME-parameter leniency; preflight and actual request recorded separately |
| Custom header (`X-Requested-With`, `X-CSRF`) | an enforced header with restrictive CORS is a real defense; look for excluded routes and hubs, permissive preflight policies, headerless alternate handlers |
| Method and route | the GET version of the action, `_method` parameters, normalization variants, legacy versions, middleware-exempt prefixes |
| GraphQL | the mutation over GET, simple-body transports, batching/aliases, persisted queries — per operation, never per endpoint |
| Client-side request builders | URL, hash, postMessage or path input reaching an authenticated request the app sends with its own token |
| OAuth / OIDC / SAML | state + PKCE + nonce bound to the browser session, link-callback swap, login CSRF, InResponseTo, RelayState as state — a redirect allowlist is a separate question from transaction binding |
| WebSocket / SignalR | handshake Origin check, cookie-authenticated connection, a protected message executed, negotiate/SSE/long-poll fallbacks |

## Chains

| Demonstrated action | Chains into | Link |
|---|---|---|
| Email, password, MFA or recovery change | reset or login as V (`hunt-ato`) | `enables` |
| Account or social-identity link | login as V through A's identity (`hunt-oauth`, `hunt-ato`) | `yields-access` |
| Role, invite or permission change | privilege escalation | `escalates-via` |
| Webhook or integration URL change | server-side fetch (`hunt-ssrf`) | `pivots-to` |
| Content written through CSRF | stored XSS in V's or staff views (`hunt-xss`) | `spawns` |
| XSS on the target origin | token read plus same-origin request | `enables` |
| Control of a same-site sibling (takeover/XSS) | same-site CSRF (`sibling-csrf-ato` chain) | `enables` |
| SAML/OAuth transaction flaws | `hunt-saml`, `hunt-oauth` | `escalates-via` |

Record the lead with `python3 -m recon finding add <campaign> --class csrf ...`, link
proven edges with `python3 -m recon finding link`, and answer the chain's realism
questions with `python3 -m recon chain realism` before impact.

## Reading the ledger

- Readiness: `ready`, `waiting-baseline`, `waiting-capture`, `needs-confirmation`,
  `waiting-effect`, `n-a-suggested` (with the reason), `n-a-baseline`.
- Outcomes: `untested`, `in-progress`, `observed`, `negative`, `blocked`,
  `inconclusive`, `n-a`, `stale`.
- Attempts are counted per case and context; `csrf.per_case_effort_cap` (default
  3) in `scope.json` flags spent effort on that one case — the action's other cases
  stay open.
- A new capture that changes token channels, cookie attributes, Origin metadata,
  request shape or header flags reopens only the cases that depend on that facet;
  earlier events stay in history as stale.
- Coarse `cov` rows for `csrf` never close open action cases; `csrf status` lists
  any row that claims otherwise.

Sources, selections and corrections: [references/sources.md](references/sources.md).
Record bundle reference: [references/evidence.md](references/evidence.md).
