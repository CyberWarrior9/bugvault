---
name: hunt-auth-bypass
description: "Login bypass hunting for authorized BugVault campaigns: test login, SSO callback, session, JWT, password-reset, magic-link and admin-login surfaces for missing authentication, client-trusted headers or cookies, JWT algorithm and key confusion, reset-token leaks, magic-link replay, session fixation and self-signup on internal identity tenants. Use for coverage rows of class `ato` and whenever a login, SSO, reset or admin-panel endpoint appears. Proofs only on operator-owned test accounts; every request goes through `python3 -m recon send`."
license: "MIT; adapted from mind-hunt (Copyright (c) 2026 MindflareX), see LICENSE.txt"
metadata:
  source: "mind-hunt skills/hunt-auth-bypass"
  source-sha256: "e71106db0762120fe429e722515505ad0bc583a6023466055da2969ce1026aab"
  adapted: "2026-11-11"
---

# Hunt: authentication / login bypass

An authentication bypass is the shortest path to account takeover, and programs pay for
it consistently. This skill finds the bypass; `hunt-ato` is what it chains into.

## When this skill applies

- `coverage.md` lists a row of class `ato` whose `skill` column names `hunt-auth-bypass`.
  `recon/score.py` seeds that row automatically for every in-scope path containing
  login, signin, signup, register, password, reset, forgot, otp, mfa, 2fa, totp, verif,
  session, token, oauth, authorize, sso, saml, change-email or recover.
- `recon.md` shows a fact "route … bounced to client login" (synthetic UI mapping), or an
  auth endpoint known only from JS, a source map or the Wayback archive
  (`/api/auth/internal`, `/sso/callback` variants, `/staff/login`, an old `/v1/` login).
- Your own test-account traffic carries a JWT, a SAML response or an OAuth redirect.

Hand off by flow: SAML → `hunt-saml`, OAuth/OIDC → `hunt-oauth`, second factor →
`hunt-mfa-bypass`, reset or email change → `hunt-ato`.

## Before the first request

1. Read `scope-policy`. Confirm the program's written rules allow authentication testing
   and that the class is not listed in `excluded_bug_classes`.
2. Create two test accounts you control, following the program's rules: **A** (attacker)
   and **V** (victim), one pair per role you need. Put a unique marker in V's profile,
   for example display name `canary_ato_<8 random chars>`, so reading V's data is provable.
3. Log in as A and as V yourself in a normal browser, export HAR, and import each:
   `python3 -m recon import-har <campaign> a.har --account A --role member`.
4. Login, OTP and reset submissions usually use POST; account APIs may also use PUT,
   PATCH or DELETE. When the program permits all these methods, set
   `policy.allowed_methods` in `scope.json` to
   `["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"]` and mode to
   `active` or `loud`. Remove any method the program forbids. OPTIONS is not a mutation,
   but still needs an explicit active-testing grant. PUT/DELETE tests use disposable
   resources owned by A or V, never real users' data. See `scope-policy` for init flags.
5. Send every test with `python3 -m recon send`. It enforces scope, the method grant, the
   campaign rate limit (across processes), request budgets and pinned egress, and stores
   each response as evidence with a `request_id`. Do not use curl or scripts with their
   own HTTP client: they bypass every one of those controls.

## Sub-classes, most frequent first

1. **SSO / SAML / OIDC flaws** — signature wrapping, audience confusion, replayed
   IdP-initiated logins. Load `hunt-saml` or `hunt-oauth`.
2. **OAuth state confusion / nonce skip** — the callback attributes the account from URL
   `state` without checking the server-side session. Load `hunt-oauth`.
3. **JWT mistakes** — see *JWT tests* below.
4. **Password-reset token leaks** — token in the URL leaking through `Referer` to
   third-party resources, token returned in the response body, predictable
   (timestamp-based) tokens. The full reset flow is in `hunt-ato`.
5. **Self-signup on internal portals** — an internal Okta/Auth0/Cognito tenant left with
   self-signup enabled. Test only tenants that are in scope, sign up with your own test
   address, and stop at the first page a visitor must not reach.
6. **Login bypass through client-trusted headers or cookies** — `X-Authenticated: true`,
   an `is_admin: 1` cookie, role or user-id values the server believes.
7. **WordPress XML-RPC `system.multicall`** — many login attempts inside one HTTP
   request, defeating per-request rate limits (Uber OneLogin cases below).
8. **Magic-link replay / cross-user replay** — reuse, expiry, and whether the link token
   is bound to the account it was issued for.
9. **Session fixation** — a session ID that exists before login is still valid after it.

## Test recipe

1. Prior work: `python3 -m recon recall <campaign> "login sso reset token session"`.
2. **Baseline:** request each auth-gated endpoint as A with A's session. Keep the
   `request_id`; A's data is present and V's marker absent.
3. **No credentials:** the same request without `Cookie`/`Authorization`, with an empty
   JSON body `{}`, and with a logged-out or expired session.
4. **Trusted headers:** repeat with `X-Authenticated: true`, `X-User-Id: <V's id>`, an
   `is_admin=1` or `role=admin` cookie, and allow-list headers such as
   `X-Forwarded-For: 127.0.0.1`. `recon send` refuses `Host` and proxy-header
   overrides by design.
5. **Hidden auth endpoints** from JS, source maps and the archive: send the same
   variants. Old API versions often lost their authentication middleware.
6. **JWT:** run *JWT tests*. **SAML / OAuth:** load `hunt-saml` / `hunt-oauth`.
7. **XML-RPC:** confirm `system.multicall` exists with one harmless `system.listMethods`
   call. To show the rate-limit bypass, send **one** multicall request carrying a few
   (at most five) wrong passwords plus the correct password for **A only**.
8. **Magic links:** request one for A; use it twice, after expiry, after a newer link was
   issued, and while signed in as V.
9. **Session fixation:** note A's session ID before login, log in, and check whether the
   same ID still works; demonstrate across two browser profiles you own.
10. **Self-signup:** if signup exists on the primary domain, try the internal or staff
    variants that are in scope.
11. Every outcome is either a lead or a dead end; record it (*Record and prove*).

```bash
python3 -m recon check <campaign> https://app.example.com/api/me
python3 -m recon send <campaign> https://app.example.com/api/me --header "Cookie: session=<A's session>"
python3 -m recon send <campaign> https://app.example.com/api/me
python3 -m recon send <campaign> https://app.example.com/api/me --header "X-Authenticated: true"
python3 -m recon send <campaign> https://app.example.com/api/login --method POST --json '{}'
```

Request header values (cookies, tokens) are sent but never written to the campaign
database; response bodies and request bodies are stored as evidence under the
campaign's private `.recon/` directory. Use dedicated test-account passwords.

## JWT tests (your own tokens only)

Decode A's token (header and claims are base64url JSON) and send each variant to an
endpoint that returns account data:

- `"alg": "none"` (also `None` and `NONE`) with an empty signature;
- signature removed while `alg` is unchanged;
- RS256 → HS256 key confusion: sign with the server's public key as the HMAC secret
  (the JWKS URL is in the OpenID configuration the `wellknown` job records);
- weak HS256 secret: crack it **offline** against A's own token
  (`hashcat -m 16500 token.txt wordlist.txt`) — no target traffic;
- `kid` injection: path traversal (`"kid": "../../../../dev/null"` with an empty key)
  or SQL injection inside `kid`;
- `jwk` embeds a key; `jku` points to a JWKS URL; `x5u` points to a certificate URL.
  For callback detection, the operator can use Burp Collaborator (Pro), not Intruder
  alone. A callback proves retrieval only, not that the server trusts the key.
  Full `jku`/`x5u` validation needs an operator-controlled HTTPS server returning the
  chosen JWKS/certificate, followed by proof of V's marker with the forged token.
  Read `.claude/skills/scope-policy/references/burp-workflow.md` before a handoff.
  Burp MCP is connected, but no campaign-enforced Burp executor exists. Keep an
  unsupported variant as a lead until the operator supplies correlated evidence,
  and never open an alternative network path
  from a generated agent brief.

Change `sub` (or the user-id claim) from A to **V**. The bypass is proven when the forged
token returns V's marker. The control is the same modified claims sent with A's original
signature and unchanged `alg`: that token must be rejected, which shows the server
otherwise verifies signatures.

## Record and prove

```bash
python3 -m recon finding add <campaign> --title "JWT alg=none accepted on /api/me" --class ato --url https://app.example.com/api/me
python3 -m recon fact check <campaign> --response <bypass_request_id> --predicate '{"type":"body_contains_raw","marker":"canary_ato_..."}'
python3 -m recon fact check <campaign> --response <control_request_id> --predicate '{"type":"status_is","expected":401}'
python3 -m recon finding link <campaign> <bypass_finding_id> escalates-via <ato_finding_id>
python3 -m recon cov <campaign> <asset_id> ato tested --note "no-creds, trusted headers, JWT variants: all 401"
```

- Body-diff rule: a 200 with the same body as the baseline is not a bypass. Show V's
  marker (or internal-only data) where the control proves it must not appear.
- Hand the lead to the validator. The reportability gate then decides: real-person harm
  (Q1) or platform harm (Q2), demonstrated on your test accounts. A bypass that only
  matters combined with something else stays a parked half finding.

## Not bugs on their own

Weak password policy; concurrent sessions allowed; email enumeration on signup (usually);
2FA required only after the first login (by design); a missing login rate limit without
a demonstrated takeover. Record them as leads when they can become chain links.

## Hard limits

- Only accounts you own. Never log in as, guess, stuff or spray credentials for anyone
  else's account.
- Bounded attempts within the program's rate rules. Stop at the first lockout, CAPTCHA or
  429 and record it: that response is the rate-limit control.
- No IP rotation or proxies to evade limits; `recon/net.py` refuses proxies.
- Minimum data: once V's marker is proven, stop reading.

## Reference cases (in BugVault's report index)

| Report | Program | Bug | Indexed bounty |
|---|---|---|---|
| #136169 | Uber | OneLogin authentication bypass on WordPress sites | $10,000 |
| #223014 | Uber | SAML authentication bypass on uchat.uberinternal.com | $8,500 |
| #138869 | Uber | OneLogin authentication bypass on WordPress via XML-RPC | $7,000 |
| #219205 | Uber | Authentication bypass on auth.uber.com via subdomain takeover | unknown |
| #143482 | Shopify | Authentication bypass on an Icinga monitoring server | unknown |
| #129918 | Slack | Authentication bypass exposing a token and secret | $2,000 |

Titles and amounts come from `vault/_data/reports-merged.csv` (source-indexed, not
reproduced); "unknown" means no indexed source reported an amount. Upstream mind-hunt
lists $5,000 for #219205 and $3,000 for #143482, which no indexed source confirms.

## Related skills

`hunt-ato` (what a bypass chains into) · `hunt-mfa-bypass` · `hunt-oauth` · `hunt-saml` ·
`service-mapping` (subdomain-takeover leads that feed SSO and OAuth chains) ·
`captured-auth-mapping` (HAR imports for A and V). Gates: `recon/prompts/validator.md`
and `vault/00-Engine/doctrine.md`.
