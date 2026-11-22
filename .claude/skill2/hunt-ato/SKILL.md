---
name: hunt-ato
description: "Account-takeover hunting for authorized BugVault campaigns, the chain target most other bugs escalate into: password-reset token leaks and reuse, reset-link host poisoning, CSRF or missing re-authentication on email, phone, password and MFA changes, OAuth account-linking state confusion, magic-link replay, email-verification bypass, subdomain takeover into OAuth callbacks or cookie scope, stored XSS into session theft. Use after a login bypass, information disclosure, XSS, OAuth flaw or weak reset flow, and for coverage rows of class `ato`. Proofs only between operator-owned test accounts A and V."
license: "MIT; adapted from mind-hunt (Copyright (c) 2026 MindflareX), see LICENSE.txt"
metadata:
  source: "mind-hunt skills/hunt-ato"
  source-sha256: "dbaf3be57f86bd96dd14cc3c60a0c59e35d0799035693a8299a771ffa98622a4"
  adapted: "2026-11-11"
---

# Hunt: account takeover

Account takeover is what most other bugs chain into. A standalone takeover pays Critical;
a chained one is what upgrades a Medium or High to Critical.

## When this skill applies

- A coverage row of class `ato` (its `skill` column lists `hunt-auth-bypass`, then
  `hunt-ato`) on a reset, forgot-password, change-email, recover or account-linking path.
- A lead to escalate: a login bypass (`hunt-auth-bypass`), an information disclosure that
  exposes tokens or email addresses, XSS, an OAuth flaw (`hunt-oauth`), a weak reset flow,
  or a `takeover-lead` fact under a parent domain whose cookies or OAuth callbacks matter
  (`service-mapping`).

## Setup

As in `hunt-auth-bypass`: two test accounts **A** (attacker) and **V** (victim) that you
own, V's profile marked with `canary_ato_<8 random chars>`, HAR imports for both,
`"allowed_methods"` including `POST` in `scope.json` when the program permits
state-changing tests, and every request sent with `python3 -m recon send`. You need both
test mailboxes to read reset and magic links.

## Sub-classes

1. **Password-reset token mishandling** — token in the URL and leaked through `Referer`,
   returned in a response body, predictable, never expiring, reusable, or accepted for
   another account.
2. **Reset-link host poisoning** — the reset email builds its link from a request header.
   `recon send` refuses `Host` overrides by design; test `X-Forwarded-Host`,
   `X-Forwarded-Server` and `Forwarded` instead, and read A's own reset email.
3. **OAuth state confusion / cross-account linking** — the callback decides which account
   receives the provider's tokens from URL `state` alone. Load `hunt-oauth`.
4. **CSRF on email or phone change** — V's email changed to an address you control, then
   "forgot password" completes the takeover.
5. **Sensitive changes without re-authentication** — email, password, phone or MFA
   changed without the current password or a fresh second factor (`hunt-mfa-bypass`).
6. **Magic-link replay / cross-user replay.**
7. **Email-confirmation bypass** — an unverified address treated as verified.
8. **Subdomain takeover → OAuth callback or cookie scope** (Uber #219205) — start from a
   `takeover-lead` fact; claiming a third-party resource needs the program's explicit
   permission.
9. **Stored XSS → cookie or local-storage token theft** — V views A's stored payload.
10. **Social-login linking confusion** — a linking flow binds the wrong identity.

## Test recipe

Password reset:

1. Trigger a reset for A and record where the token travels: URL query or fragment,
   response body, header, or email only.
2. Token in the URL: open the reset page and list the third-party scripts, images and
   links that would receive it in `Referer` (stored responses and `recon.md` show them).
3. Collect a few tokens for A (five is enough) and look for timestamp or sequential
   structure.
4. Submit V's reset token while signed in as A (cross-user acceptance).
5. Reuse an expired token, an already used token, and an older token after a newer one
   was issued.
6. Open the reset link as A and submit the form as V.
7. Repeat the reset request with `X-Forwarded-Host: <a host you control>` and check the
   link in A's email.

```bash
python3 -m recon send <campaign> https://app.example.com/api/password/forgot --method POST --json '{"email":"a@your-test-domain.example"}'
python3 -m recon send <campaign> https://app.example.com/api/password/forgot --method POST --json '{"email":"a@your-test-domain.example"}' --header "X-Forwarded-Host: your-host.example"
```

Email change:

1. Capture A's change-email request from the HAR (method, path, parameter names).
2. Is there a CSRF token, is it bound to the user, are `Origin` and `Referer` checked?
3. Re-send it for A without the CSRF token and without the current password.
4. If that succeeds, demonstrate the cross-site version against **V** from a PoC page you
   open in V's browser profile; export that session as HAR and import it.
5. If the new address is accepted, complete "forgot password" with it.

OAuth state confusion (details in `hunt-oauth`):

1. A starts the OAuth flow and captures `state`.
2. V completes the identity-provider step using A's `state`, in V's browser profile.
3. Check which account ends up linked. V's identity attributed to A is high severity.
4. If one dispatcher serves several providers, test each provider.

MFA changes (details in `hunt-mfa-bypass`): change the MFA secret, disable MFA, or reuse
a backup code without re-authentication, on A.

## Proof

V's marker read through A's session, or A holding a working session for V without V's
credentials. Keep the replay (the takeover request) and a control (the same request
refused when the flaw is absent, for example with a fresh token or a properly bound
flow), then:

```bash
python3 -m recon finding add <campaign> --title "Reset token accepted cross-user on /api/password/reset" --class ato --url https://app.example.com/api/password/reset
python3 -m recon fact check <campaign> --response <request_id> --predicate '{"type":"body_contains_raw","marker":"canary_ato_..."}'
python3 -m recon finding link <campaign> <primitive_finding_id> escalates-via <ato_finding_id>
```

The validator brief and the reportability gate decide what is reported: Q1 (real-person
harm) is shown by the takeover of V, your own test account.

## Chain up

- Takeover of an admin or staff test account supplied by the program → state the
  company-wide impact; never perform it on real staff accounts.
- Takeover → remote code execution when the admin panel has template injection.
- Scale: demonstrate on A and V only, then describe the affected population from the
  vulnerable code path in the report. Never test against real users' accounts.

## Reference pattern

OAuth callbacks that attribute the user from URL `state` alone (documented upstream from
the mind-hunt author's Manus reports, CVSS 9.6). Whenever an OAuth callback accepts user
attribution from URL state, suspect this class.

## Reference cases (in BugVault's report index)

| Report | Program | Bug | Indexed bounty |
|---|---|---|---|
| #173551 | Uber | Password-reset token leaking allowed account takeover | $10,000 |
| #143717 | Uber | Change any user's password through /rt/users/passwordless-signup | unknown |
| #136885 | Uber | Complete account takeover | $8,000 |
| #192648 | Pornhub | Account takeover via Pornhub OAuth | $1,000 |
| #127703 | Bumble (Badoo) | Full account takeover using CSRF | unknown |
| #121827 | Bumble (Badoo) | Account takeover | unknown |
| #50703 | Ubiquiti | CSRF in the login form leading to account takeover | unknown |

Source-indexed, not reproduced; "unknown" means no indexed source reported an amount.
Upstream also cites Twitter #174500 (circumventing account lockout), which is not in
BugVault's index.

## Hard limits

Only accounts you own; no credential guessing, stuffing or spraying against anyone
else's account; bounded attempts within the program's rate rules; stop at lockout,
CAPTCHA or 429; minimum data once V's marker is proven.

## Related skills

`hunt-auth-bypass` (bypasses that feed takeover) · `hunt-mfa-bypass` · `hunt-oauth` ·
`hunt-saml` · `service-mapping` (takeover leads). Gates: `recon/prompts/validator.md`,
`vault/00-Engine/doctrine.md`.
