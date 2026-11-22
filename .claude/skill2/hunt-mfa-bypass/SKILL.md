---
name: hunt-mfa-bypass
description: "MFA / 2FA bypass hunting for authorized BugVault campaigns: MFA not enforced on sensitive endpoints, the MFA step skipped with the pre-MFA session, OTP reuse, missing OTP rate limits proved with a bounded run (never the full code space), response manipulation that yields a real server session, recovery codes exposed in API responses, backup-code reuse, unbound remember-device trust and weaker fallback factors. Use for coverage rows of class `mfa-bypass`, any OTP, 2FA or verify endpoint, and chains that need a post-MFA session. Proofs only on operator-owned test accounts."
license: "MIT; adapted from mind-hunt (Copyright (c) 2026 MindflareX), see LICENSE.txt"
metadata:
  source: "mind-hunt skills/hunt-mfa-bypass"
  source-sha256: "4af980aa272a9d3d2b9f0562df5f4170f1ee6980a3260bcee521645efa2d0662"
  adapted: "2026-11-11"
---

# Hunt: MFA / 2FA bypass

A growing class. It pays High or Critical when it enables account takeover without a
prior session.

## When this skill applies

- A coverage row of class `mfa-bypass`: `recon/score.py` adds it for in-scope paths
  containing otp, mfa, 2fa, totp or verif.
- A chain that needs a post-MFA session, or an MFA prompt in your own test-account HAR.

## Setup

As in `hunt-auth-bypass`: test accounts **A** and **V** that you own, MFA enabled on
both, HAR imports, `"allowed_methods"` including `POST` in `scope.json` when the program
permits state-changing tests, and every request sent with `python3 -m recon send`.
For other API methods use the full grant in `hunt-auth-bypass`; unlisted methods stay
blocked. Pattern 6 is an operator-only Burp handoff, not permission for an agent to
use another network client.
First trace the whole login: which state transitions exist, and whether MFA is enforced
once in middleware or separately on each endpoint.

## Patterns

1. **MFA not enforced on sensitive endpoints** — with A's password-only (pre-MFA) session,
   or a full session without step-up, change email, password, phone or MFA settings.
   Proof: the change succeeds without an MFA challenge.
2. **MFA step skipped (workflow bypass)** — after the password step the app sets a
   pre-MFA cookie and redirects to `/mfa`. Request post-login pages **and** API endpoints
   directly with that cookie; route gates are often placed on pages only.

   ```bash
   python3 -m recon send <campaign> https://app.example.com/dashboard --header "Cookie: session=<A's pre-MFA session>" --no-follow
   python3 -m recon send <campaign> https://app.example.com/api/me --header "Cookie: session=<A's pre-MFA session>"
   ```

   Proof: A's data returned with the pre-MFA session; control: no session gives 401.
3. **OTP reuse** — log in and use a code; log out, log in again, submit the same code.
   Accepted means codes are never invalidated.
4. **No rate limit on OTP verification — bounded proof only.** Never iterate the code
   space. On **A's** account:
   - send a bounded batch of wrong codes (25 at most, fewer if the program sets a lower
     rate or volume limit) through `recon send`;
   - then send the currently valid code. Accepted, with no lockout or CAPTCHA, shows
     no limit was observed at that tested count, not that attempts are unlimited;
   - stop at the first 429, lockout or CAPTCHA and record it as the control.

   Send one request at a time and inspect the response before the next; an unchecked
   shell loop cannot stop on lockout or CAPTCHA. If the operator uses Intruder for this
   bounded check, configure one concurrent request, a fixed finite payload list and a
   delay matching the program's rate limit. Inspect the results and stop on a control.
   Follow `.claude/skills/scope-policy/references/burp-workflow.md` first: Intruder
   traffic is not enforced or counted by BugVault.

   `recon send` paces every invocation to the campaign's `max_rps`, even across separate
   processes, and the persistent campaign budget counts each attempt. In the report,
   calculate feasibility instead of performing it: 1,000,000 codes divided by the accepted
   request rate, compared with the code's lifetime.
5. **Response manipulation** — in your own browser with an intercepting proxy, change
   `{"success": false}` to `true` (or 401 to 200) for A's wrong code. It matters only if
   the server then issues a post-MFA session: check with `recon send` to `/api/me` using
   the resulting cookie. Progress in the UI while API calls still fail is not a bypass.
6. **OTP race** — BugVault's scoped client is sequential; its burst executor is not
   built. For an operator-run test, prefer Burp Repeater **Send group in parallel**
   (HTTP/2 single-packet or HTTP/1 last-byte synchronization). Intruder concurrency
   does not guarantee synchronization, so a negative Intruder result does not rule out
   a race. Start with two requests against A's own account and a known test code,
   only when the program explicitly allows the burst; do not enumerate OTP guesses.
   Compare a sequential control with a fresh equivalent challenge, save timestamps,
   raw responses and post-MFA state. Two 200s alone are not a bypass. Follow
   `.claude/skills/scope-policy/references/burp-workflow.md` for prerequisites,
   evidence and fallback. Without the required permission/tool/evidence, record the
   hypothesis with `finding add --class mfa-bypass` and park it. Generated agents
   must not launch Burp to bypass the scoped client.
7. **Recovery codes exposed** — look in A's own `/api/me`, settings or export responses
   for `backup_codes` or `recovery_codes`. With any read primitive on V (IDOR, XSS), V's
   codes become an MFA bypass: link the findings.
8. **Backup codes** — on A: reuse a used code; check length and character set (entropy);
   check whether regenerated codes are predictable. Never try to guess codes.
9. **Remember-device trust** — complete MFA as A in browser profile 1, capture the
   remember-device cookie, present it from profile 2 on another network. MFA skipped with
   an unbound cookie is trust escalation.
10. **Weaker fallback factor** — SMS or email fallback without the primary factor's
    limits or binding. The bounded-proof rule of pattern 4 applies.

## Severity guide

| Result | Typical severity |
|---|---|
| Post-MFA data with the pre-MFA session (step skip) | Critical |
| Response manipulation that yields a real server session | Critical |
| OTP accepted after reuse | High |
| No effective OTP limit (bounded proof plus feasibility) | High; Critical with a proven primitive that supplies the first factor |
| Bypass that needs the victim's password and nothing else | High |

## Record and prove

```bash
python3 -m recon finding add <campaign> --title "MFA step skipped: /api/me served to pre-MFA session" --class mfa-bypass --url https://app.example.com/api/me
python3 -m recon fact check <campaign> --response <request_id> --predicate '{"type":"body_contains_raw","marker":"canary_ato_..."}'
python3 -m recon finding link <campaign> <mfa_finding_id> enables <ato_finding_id>
```

Hand the lead to the validator; the reportability gate decides. An MFA bypass alone is a
primitive: the attacker still needs the first factor, so finish the chain in `hunt-ato`
before claiming a takeover.

## Chains

- Cookie theft (XSS or session fixation) + no step-up on password change = persistent
  takeover without ever meeting the OTP challenge.
- Pre-MFA cookie + a route gate on `/mfa` only = full post-login access from the
  password step (`hunt-auth-bypass`).
- `/api/me` returning recovery codes + a read IDOR or XSS on V = MFA satisfied without
  an OTP.

## Hard limits

Only accounts you own; never iterate the full code space; bounded attempts within the
program's rate rules; stop at lockout, CAPTCHA or 429; no IP rotation or proxies; MFA
fatigue prompts only against your own test devices.

## Related skills

`hunt-ato` (the destination) · `hunt-auth-bypass` (workflow-layer bypasses) ·
`hunt-oauth` · `hunt-saml`. Gates: `recon/prompts/validator.md`,
`vault/00-Engine/doctrine.md`.
