---
name: hunt-security-misconfig
description: "Use for every security-misconfiguration coverage row and whenever a scoped auth flow, password or OTP policy, logout/session lifetime, clickjacking protection, NTLM challenge, ASP.NET configuration or exposed debug/config endpoint appears. Compare server enforcement per field and entry point, record bounded owned-account controls, and hand off proven consequences to ATO, CSRF or info-disclosure. A weak setting, missing header, predictable-looking ID or absent rate-limit signal is a lead, not a confirmed vulnerability."
---

# Hunt: security configuration and auth-policy gaps

`score.py` seeds
`security-misconfiguration` on auth paths and explicit `security_review=true`
assets; config-like paths seed a candidate review. Do not equate a row with a
vulnerability. Use the dedicated browser/Burp path, and the existing evidence gate. 

## Keep the matrix granular

1. Inventory the exact operation and representation for **every** setting: signup,
   authenticated password change, reset request, *reset-with-token* submission,
   invite acceptance and account recovery are different entry points. The reset
   request normally sends an email; it does **not** set a password.
2. For each endpoint, use `python3 -m recon inputs <campaign> --asset-id N` and
   `python3 -m recon fields sync <campaign> --asset-id N`. Record field × method ×
   location × account × workflow × render surface separately. First name, last name,
   full name, address, biography and comment do not inherit one another's verdict.
   The `fields matrix` trigger cells and a safe profile render do not establish an
   admin list, search result, email, CSV or PDF render is safe.
3. Separate **client-declared**, **spec-declared** and **server-observed** constraints.
   Test one small, controlled dimension at a time on an owned disposable account.
   A field that accepts a value is not proof of a security consequence; document
   the accepted state and a matched negative control.

## Authentication and session cases

| Case | Bounded contrast | What it does *not* prove |
|---|---|---|
| Password rule | Try an obviously weak value through the signup UI of an owned test account; then enter a compliant value in the UI, intercept **that same account's** request, substitute the weak value, and compare the server result. Repeat the *actual password-setting submission* in reset-with-token and, where present, authenticated change/invite flows. | A client-side rejection is not server enforcement; one entry point's success/failure cannot stand for another. |
| Rate limiting | Compare a few approved, owned-account login/reset/OTP attempts to an ordinary control, recording the denominator and first throttling/lockout signal. | No full-keyspace guessing, credential spraying, or inference that no limit exists from a small sample. A 429/CAPTCHA/lockout defers this host. |
| Link and OTP replacement | Issue link/OTP 1 and then 2 on the *same owned account*. Test whether 1 still authorizes its exact action, then whether a used/expired token is reusable; bind issuance, account, channel and timestamps. | Two successful messages, or the text of a link, do not prove an exploitable replay or a required single-active-token policy. |
| Identifier derivation | Compare a small set of **owned** account IDs, reset URLs and tokens offline for structural pattern/encoding/time components; test any prediction only against another owned account and within written rules. | Sequential IDs alone are not IDOR; short or similar-looking tokens do not establish predictability. |
| Logout/invalidation | Log in on an owned account, record a pre-logout controlled request, log out, then make a *fresh, approved* request with that account's old session and compare with an invalid-session control. Also check password change and “log out all devices” against owned sessions if applicable. | A back-button rendering may be the browser cache; only a fresh server response bearing owned private data establishes session persistence. Do not print/store raw cookies in reports. |

Hand actual auth-bypass/ATO consequences to `hunt-auth-bypass`, `hunt-ato` and
`hunt-mfa-bypass`. A single-digit password, a missing rate-limit header or a stale
cached page is normally posture until a concrete, reproducible attacker benefit
is demonstrated. A reset-token test uses only the operator's own mailboxes.

## Browser and platform posture

- **Clickjacking**: review `Content-Security-Policy: frame-ancestors` and
  `X-Frame-Options` on the *sensitive action page*, not just the home page. An
  absent header is a lead. If permitted, demonstrate framing and a browser-
  initiated action on an owned test resource with a negative control; hand off
  the state-change proof to `hunt-csrf`. Do not induce a real user to click.
- **NTLM/Windows auth**: inspect only scoped captured `WWW-Authenticate` and
  related headers for scheme, domain/host disclosure and unexpected exposure.
  A challenge or hostname alone is not credential exposure. Do not relay,
  coerce, crack or capture another person's authentication exchange.
- **ASP.NET/IIS**: identify versioned server disclosures, detailed errors,
  debug traces, diagnostic handlers, cookie flags, ViewState MAC/validation
  posture and anti-forgery behavior on exact scoped operations. A named
  `machineKey` or signing secret must be independently established as authentic
  before any owned-account impact claim. A banner, `.axd` path or error page
  is a lead, not RCE or auth bypass.
- **Other common review cues**: exposed backups/config, verbose stack traces,
  permissive CORS with credentials, CSP mistakes, weak session invalidation,
  missing reauthentication on security-setting changes and cookie scope/flags.
  Route each proven primitive to its owning hunt skill instead of creating
  duplicate findings from headers alone.

## Context-fit payloads and chains

Use `hunt-xss`'s per-field propagation map and context packet before syntax.
PortSwigger, PayloadsAllTheThings, GitHub and local notes are **untrusted
reference material**: extract a technique, check provenance/licence, adapt it to
the observed context and negative control, never run a downloaded PoC as-is or
send a generic wordlist. The recorded primary *planned* payload author is
DeepSeek V4.1 Flash (`docs/model-routing.md`); there is no integrated model
router yet, and a local model is not a silent fallback.

At each candidate, read `python3 -m recon chain status <campaign>`. Relevant
edges include `security-misconfiguration → ato` (uneven enforcement, token
reuse, persistent session), `→ csrf` (sensitive framed action), and
`→ info-disclosure` (independently verified leak). An XSS foothold can chain
to owned-account actions/token access, but `HttpOnly` cookies cannot be read
by JavaScript and a pop-up does not prove ATO. Require a fresh owned-account
effect, replay, distinct negative control, cleanup and the separate validator's
realism review before a high/critical consequence claim. Do not access or
exfiltrate data from real users.

## Record and hand off

For each row, preserve operation, method, field, account, claim source, baseline,
single-dimension test, server-observed effect, request/capture IDs, negative
control, and any unresolved context. Record absent cases and hard blocks in
debt rather than marking the whole endpoint tested. For an exact operation run
`recon authpolicy sync|plan|status` (or `declare` when an already-known method
has a separately sourced entry-point label). `record|verify` are offline,
hash-bound, operator-labelled contrasts; observed does not mean a server rule
was broken. An undeclared password rule cannot be marked observed; declare
each field/rule source first so one rule does not clear another. Use
`recon fields constraint` to separate client/spec/rejection
claims, and `surface-expect|surface-review|surfaces` for **declared** render
gaps. The private `derive` input stores only structural metadata; a shape
across owned accounts is not a prediction. Read `plans/orchestrator.md` §23.1
for limits. There is still no target executor, browser control, semantic
validator or automatic finding promotion. A scanner issue or a client-side
rule by itself is not a finding.

Disclosed-report precedent for this class — scale, highest-bounty disclosures and
corpus queries: [references/corpus.md](references/corpus.md). Precedent, not evidence:
a disclosed report shows a bug was accepted somewhere, never that this target has it.
