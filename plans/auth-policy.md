# Build plan — `hunt-auth-policy`

> **Adoption checkpoint (2026-11-21):** The existing `security-misconfiguration`
> class, `hunt-security-misconfig` and ATO/CSRF/info-disclosure handoffs remain the
> owners; **no second `auth-policy` class was created**. `recon authpolicy` now
> implements an offline exact-operation/case inventory, hash-bound receipt review
> and transient, value-free sample *shape* analysis. `recon fields constraint` and
> `surface-expect|surface-review|surfaces` provide provenance and a declared
> field × render × case gate. Engagement debt and the offline push validator are
> integrated. Sections below describe the original proposal, not all current
> implementation: the proposed raw `auth_samples.value`, status-only proof,
> standalone class/skill and target-sending cases were **not** adopted. See
> `plans/orchestrator.md` §23.1 for the implementation boundary.

Authentication-policy enforcement hunting for BugVault: where a credential rule is
enforced, which entry points skip it, what fails to be invalidated, and whether
identifiers and tokens are derivable.

Drafted 2026-11-21. Target branch `recon-engine`.
Baseline: 26 routed classes, `hunt-ato` / `hunt-auth-bypass` / `hunt-mfa-bypass`
installed. No `auth-policy` class, module, ledger or chain edge exists.

---

## 1. Corpus position

From `vault/_data/reports-merged.csv` (15,443 rows, column `class`):

| Class | Rows | Bounty rate | Priced | Median | Mean | Max |
|---|---|---|---|---|---|---|
| `info-disclosure` | 1,596 | 38% | 319 | $500 | $1,136 | $15,000 |
| `idor-bola` | 1,216 | 46% | 313 | $500 | $1,963 | $35,000 |
| **`auth-bypass`** | **863** | **43%** | 203 | $500 | $1,448 | **$20,000** |
| `rce` | 650 | 42% | 153 | $1,000 | $3,696 | $33,510 |
| `ato` | 16 | 25% | 1 | $500 | $500 | $500 |
| `mfa-bypass` | **0** | — | — | — | — | — |
| `access-control` | **0** | — | — | — | — | — |

### The same convergence pattern as RCE

`auth-bypass` holds **863 rows**; `ato` holds 16; `mfa-bypass` and `access-control`
hold **zero**. Those three classes are active in our engine and the corpus does not
label anything under them — auth findings are filed as `auth-bypass`.

This is precisely the shape found when building `rce`: a cluster of surfaces whose
outcomes all get reported under one label. The lesson transfers. `auth-policy` is a
**source class** feeding that cluster, not a competitor to it, and its findings will
be reported as `auth-bypass` or `ato`. Its own coverage rows exist to make sure the
policy surfaces get examined, not to generate a new report label.

---

## 2. The gap is a mechanism, not a doctrine

`.claude/skills/hunt-auth-bypass/SKILL.md:155-158` already states the correct
position, under the heading **"Not bugs on their own"**:

> Weak password policy; concurrent sessions allowed; email enumeration on signup
> (usually); 2FA required only after the first login (by design); a missing login rate
> limit without a demonstrated takeover. **Record them as leads when they can become
> chain links.**

That is right, and it is what the operator independently asked for: these are chain
sources into ATO, not standalone submissions.

**Historical gap:** before the orchestrator's offline slice there was nowhere to
record these candidates. `security-misconfiguration → ato` now exists, and
`authpolicy.py` records per-operation review receipts under that class. Neither a
chain hint nor a receipt proves a takeover.

**This plan builds the mechanism for guidance that already exists.**

---

## 3. What the three installed skills already cover

Do not duplicate any of this.

| Covered | Where |
|---|---|
| Reset tokens returned in a body, predictable, never expiring, reusable | `hunt-ato:36` |
| Collect ~5 tokens for A, look for timestamp or sequential derivation | `hunt-ato:63` |
| Reuse an expired token, a used token, **and an older token after a newer one** | `hunt-ato:66` |
| Magic-link replay, reuse, expiry, cross-user replay | `hunt-auth-bypass:68` |
| Token returned in response body, predictable | `hunt-auth-bypass:59` |
| OTP reuse after a successful login | `hunt-mfa-bypass:48-49` |
| Missing OTP rate limit, bounded proof only, never the full code space | `hunt-mfa-bypass:50-61` |
| Backup-code reuse, length and charset entropy | `hunt-mfa-bypass:88` |

So of the operator's five techniques, **two are already built**: old-token-after-newer
(`hunt-ato:66`) and identifier/token patterns (`hunt-ato:63`).

What is missing is everything about **where a rule is enforced**, and most of the
invalidation matrix.

---

## 4. Organizing thesis — enforcement location, not rule strength

"Is the password policy weak?" is the wrong question. A policy that rejects `1` at
signup and accepts it at password-reset is not weak, it is **unevenly enforced**, and
that is both more common and more exploitable.

So every case in this class asks one of three questions:

1. **Where is the rule enforced?** Client only, server, or server on some entry points
   and client on others.
2. **What should this event invalidate, and does it?**
3. **Is this identifier or token derivable from something the attacker knows?**

---

## 5. Enforcement location — the client-side-bypass method

The operator's second technique generalised:

```
enter a compliant value in the UI
  -> intercept before it leaves
  -> replace with a value the UI would have refused
  -> observe the server
```

Three outcomes:

| Server response | Meaning |
|---|---|
| rejects with the same rule the UI stated | enforced server-side; not a finding |
| accepts | **enforced client-side only** |
| rejects on entry point A, accepts on entry point B | **unevenly enforced** — §6 |

**This is not password-specific and should not live only here.** Any field with a
stated client constraint — length, format, range, enum, file type, quantity, **price**
— is testable the same way. It belongs in `fields.py` as a **constraint dimension**
beside the existing name dimension.

`AGENTS.md` describes `recon fields diff` as comparing "sent versus declared names
without claiming server acceptance". Adding constraints extends the same machinery:

```
declared_constraints(asset_id, field, kind, value, source)
    kind   in ("minlength","maxlength","pattern","min","max","enum","accept","required")
    source in ("html-attr","js-validator","openapi","json-schema","observed-rejection")
```

`source` matters: a constraint read from an HTML attribute or a JS validator is a
*client* claim. One read from OpenAPI or a JSON Schema is a *declared* claim. One
inferred from a server rejection is an *observed* claim. Only the third is evidence of
server enforcement, and the case is precisely the gap between claim and observation.

---

## 6. Entry-point matrix — password policy

A password can be set or changed at many entry points, and the policy is frequently
enforced at only some. Each is its own row.

| Entry point | Notes |
|---|---|
| signup | almost always enforced; the control case |
| authenticated change (with current password) | |
| forgot-password request | |
| **reset-with-token** | the classic gap — operator's technique 3 |
| admin-set / invite acceptance | often skips the user-facing validator entirely |
| **API-direct, no UI** | no client validator exists to skip |
| OAuth-linked account setting a local password for the first time | |
| support or recovery flow | |

The existing `field_cases` key already guarantees the matrix cannot be collapsed —
`fields.py:56`:

```sql
UNIQUE(asset_id, method, location, field, account, case_id)
```

A pass on signup cannot mark reset as tested. The operator's "one safe field doesn't
mean all are safe" is already the primary key; this plan extends the same discipline
from *fields* to *entry points* for one named rule.

### Cases

| Case | Establishes |
|---|---|
| `ap-policy-stated` | what the client claims the rule is, per entry point |
| `ap-policy-server` | whether the server independently enforces it |
| `ap-policy-client-only` | the UI refuses, the server accepts |
| `ap-policy-uneven` | enforced at entry point A, not at B |
| `ap-policy-absent` | no rule stated or enforced anywhere |

---

## 7. Invalidation matrix

Four of these are uncovered, and they are the ones that chain.

| Event | Should invalidate | Status |
|---|---|---|
| a newer reset link is issued | the older link | covered, `hunt-ato:66` |
| a reset link is used | that link | covered |
| **password changed** | **every other active session** | **new** |
| **password changed** | **outstanding reset links** | **new** |
| **email changed** | **links already sent to the old address** | **new** |
| a newer OTP is issued | the older OTP | covered, `hunt-mfa-bypass` |
| OTP used | that OTP | covered |
| max OTP attempts reached | the challenge | partial |
| **logout** | **that session token, server-side** | **new** |
| "log out all devices" | every session | **new** |
| MFA enabled or disabled | other sessions | **new** |

### The back-button case, stated carefully

The operator's test — log in, log out, press Back — has a false positive built into it.
A rendered authenticated page after Back may simply be the browser's own history
cache. Three outcomes:

| Observation | Meaning | Case |
|---|---|---|
| page renders, but any action or refresh bounces to login | browser cache only; session is dead server-side | `ap-cache-authenticated` — a posture lead |
| page renders **and a fresh request bearing the old cookie succeeds** | logout never invalidated server-side | `ap-logout-noop` — the finding |
| login page | correct | no case |

**The decisive test is not the back button.** Capture the session cookie, log out, then
replay an authenticated request with that cookie **outside the browser**, where no
cache exists. A 200 carrying the account's own data is the proof; the browser is not
part of the evidence.

Record both separately. The cache observation is `Cache-Control: no-store` posture and
is a lead at best. The replay is a **persistence primitive**: after any ATO, a victim
who logs out does not evict the attacker. That is what makes it chain rather than sit
as informational.

Special case worth its own row: **JWT logout that only deletes the client-side token.**
Common in SPAs, and it means the credential is valid until natural expiry with no
server-side revocation at all. The test is identical — replay after logout.

---

## 8. Derivability — identifiers and tokens

`hunt-ato:63` already says to collect about five tokens and look for timestamp or
sequential structure. Extend it into a derivation test over a small sample ledger, so
the result is measured rather than eyeballed.

| Derivation | Test |
|---|---|
| sequential | two samples, numeric or near-numeric delta |
| timestamp-derived | UUIDv1 or v6, epoch-looking integer, monotonic ordering |
| encodes a known value | base64/hex decode → user id, email, username, epoch |
| hash of a known value | compare against `md5`/`sha1`/`sha256` of email, id, username, with and without a guessed static salt |
| short enough to enumerate | length × charset vs the program's rate rules |
| account id guessable | sequential, short, or derived from signup order |
| reset URL structurally guessable | fixed path plus a derivable parameter |

All offline once samples are collected. No payload is involved, so nothing here needs
the generator model.

Store as a sample ledger:

```
auth_samples(asset_id, kind, account, value, observed_at, request_id)
    kind in ("reset-token","otp","account-id","session-id","invite-code","verify-token")
auth_derivations(sample_kind, derivation, result, basis, checked_at)
```

Two accounts matter here: a derivation that only holds for account A is coincidence; a
derivation that predicts B's token from A's is the finding.

---

## 9. Rate limiting stays inside this class

Rate limiting is not given its own class, because on its own the installed doctrine
already calls it "not a bug" — *"a missing login rate limit without a demonstrated
takeover"* (`hunt-auth-bypass:157`). It becomes a finding only as
`auth-policy → ato`, which is the edge this class creates.

OTP rate limiting stays with `hunt-mfa-bypass`, which already has the bounded-proof
rule. This class covers rate limits on **password** entry points: login, password
reset request, password change, and the reset-token submission.

Bounded proof only, and the first lockout, CAPTCHA or 429 **is** the control — record
it and stop, per `hunt-auth-bypass:163-165`.

---

## 10. Original proposed chain edges (not automatically installed)

The historical chain audit found 12 of 26 routed classes with no edge in either
direction. The adopted ledger does not create another class. The existing
`security-misconfiguration → ato|csrf|info-disclosure` hints remain conditional;
the other proposed edges below were **not** added as blanket chain rules.

| Edge | Why |
|---|---|
| `auth-policy → ato` | the primary edge. Client-only policy, uneven enforcement, derivable token or absent rate limit → guessable or settable credential → takeover |
| `auth-policy → access-control` | a password set through an admin or invite path that skips validation may also skip role assignment |
| `auth-policy → info-disclosure` | token derivation often reveals internal ids, signup order, or user counts |
| `subdomain-takeover → auth-policy` | a sibling origin that can read a parent-domain session cookie makes an un-invalidated session reachable |
| `info-disclosure → auth-policy` | a leaked `machineKey` or signing secret turns a token into a forgeable one |

`ap-logout-noop` specifically is a **post-condition** on every ATO chain: once any
chain reaches `ato`, an un-invalidated session is what makes the access persistent.
Record it as a chain property, not a separate finding.

---

## 11. The `matrix()` surface gap

Found while auditing per-field discipline, and it belongs in this plan because it is
the same principle one level deeper.

`fields.py:65-75` already tracks render surfaces:

```sql
CREATE TABLE canary_events(
  marker, asset_id, surface, encoding, request_id, source, ...
  UNIQUE(marker, surface, encoding, source));
```

Marker → surface → encoding. So "escaped on the profile page, raw in the admin user
list" is already two distinct rows, and the data exists today.

But `matrix()` buckets observations into the eight `TRIGGERS` and reports per-trigger
cells. It never consults `canary_events`. So:

- Field names are separately keyed in `field_ledger`, but its legacy key omits
  role, tenant and workflow; auth-policy contexts now use a separate exact key.
- Render reviews are now gated **only for declared expected surfaces**, not every
  surface that might exist on an undiscovered page.

The implemented gate uses **declared expected** field × surface × case ×
account/workflow pairs and matching complete canary captures, rather than
counting only observed pairs (which could never reveal an unvisited render).
An empty expectation inventory remains unknown. It does not discover every
possible admin/email/export surface automatically.

Surfaces that most often escape the first sanitizer: CSV/XLSX export (formula
injection), PDF and invoice rendering (server-side renderer → SSTI/SSRF/file read),
the admin user list (different template, and the victim is an admin), email templates,
mobile/API JSON (often unescaped because "the client doesn't render HTML"), admin log
viewers, and search-result highlighting.

---

## 12. Original proposed class, seeding and wiring (superseded)

```python
SKILLS_FOR_CLASS["auth-policy"] = ("hunt-auth-policy", "hunt-auth-bypass")
SEEDED_BY["auth-policy"] = "score.py"
```

This snippet is **not implemented**. Current wiring uses the existing
`security-misconfiguration` row and skill plus `authpolicy.py`'s offline
per-operation debt, with no new coverage class or skill-count change.

Seeded from `score.py`'s existing `AUTH_PATH` match — `login|signin|sign-in|signup|
register|password|passwd|reset|forgot` — so any auth entry point already detected
gets a row without new detection code.

Wiring:

- `recon/catalog.py` — one `HUNT_SKILLS` entry
- `tests/test_recon_skills.py` — `ORIGINAL_HUNT_SKILLS:29` += 1; `len(skill_dirs())`
  at `:158` +1. The set-equality assertions at `:105-106` and `:112-113` then pass
  unedited
- `recon/skillmap.py` — route plus `SEEDED_BY`
- `recon/findings.py` — the five `CHAIN_HINTS` edges from §10
- `recon/fields.py` — the `declared_constraints` table (§5) and the surface gate (§11)
- `AGENTS.md` — a paragraph in house style, stating the ledger is offline, that a
  policy observation is a lead rather than a finding, and that proofs are between
  owned test accounts only

---

## 13. Implementation shape

### Original proposed `recon/authpolicy.py` shape (superseded)

```
ENTRY_POINTS = ("signup", "change", "forgot", "reset", "admin-set",
                "api-direct", "oauth-link", "recovery")
RULES        = ("minlength", "complexity", "blocklist", "reuse", "username-match")
CASES        = ("ap-policy-stated", "ap-policy-server", "ap-policy-client-only",
                "ap-policy-uneven", "ap-policy-absent",
                "ap-invalidate-session", "ap-invalidate-reset-link",
                "ap-invalidate-email-change", "ap-logout-noop",
                "ap-logout-all-noop", "ap-jwt-client-only",
                "ap-cache-authenticated",
                "ap-derive-token", "ap-derive-account-id",
                "ap-ratelimit-login", "ap-ratelimit-reset")

policy_rows      (asset_id, entry_point, rule, stated, enforced, basis)
invalidation_rows(asset_id, event, target, outcome, replay_request_id)
auth_samples     (asset_id, kind, account, value, observed_at, request_id)
auth_derivations (sample_kind, derivation, result, basis, checked_at)
```

The implemented ledger stores **no raw token values**. Neither a candidate value
nor a generator model is required to run offline inventory and structural review;
any future model-authored live probe still follows `docs/model-routing.md`.

### Original proposed CLI (use `recon authpolicy --help` for implemented verbs)

```
recon authpolicy sync    <campaign>              seed entry points from AUTH_PATH assets
recon authpolicy declare <campaign> --asset-id N read client-stated constraints
recon authpolicy plan    <campaign> --asset-id N ordered cases for this surface
recon authpolicy record  <campaign> ...          one case outcome with its artifact
recon authpolicy sample  <campaign> --kind reset-token --account A
recon authpolicy derive  <campaign> --kind reset-token    offline derivation tests
recon authpolicy status  <campaign>              matrix of entry_point x rule x case
recon authpolicy verify  <campaign>              artifact and account-ownership gates
```

---

## 14. Original proposed proof predicates (insufficient on their own)

| Case | Predicate | Note |
|---|---|---|
| `ap-policy-client-only` | `status_is` 2xx on the non-compliant submission | plus the client-stated constraint as a stored artifact |
| `ap-policy-uneven` | `status_is` differing across two entry points | both responses bound |
| `ap-logout-noop` | `body_contains_raw` marker = the account's own data, on a post-logout replay | the replay must be outside the browser |
| `ap-cache-authenticated` | `header_present` / `header_equals` on `Cache-Control` | posture only |
| `ap-invalidate-session` | `body_contains_raw` on session A after a change in session B | |
| `ap-derive-token` | offline; derivation result plus the sample ledger | no predicate needed |
| `ap-ratelimit-*` | `status_is` on the control that proves the limit exists | the lockout is the control |

`factcheck.FIELDS` carries exactly four predicates and no negation. A 2xx, a
rejection or a post-logout body marker alone does **not** establish a broken
rule: validate owned-state readback, intended policy, a fresh server response,
attack preconditions and a distinct control. The implemented ledger records
operator-labelled contrasts, not semantic proof or finding promotion.

---

## 15. Evals

| Eval | Asserts |
|---|---|
| `entry-point-no-collapse` | a pass at `signup` leaves `reset` untested |
| `client-claim-not-server-proof` | a constraint with `source=html-attr` never satisfies `ap-policy-server` |
| `back-button-not-proof` | a rendered page without a bound post-logout replay cannot reach `ap-logout-noop` |
| `replay-outside-browser` | `ap-logout-noop` requires a stored request whose source is not the browser profile |
| `derivation-needs-two-accounts` | a derivation holding only for account A is not a finding |
| `ratelimit-control-required` | `ap-ratelimit-*` needs the lockout or 429 response stored |
| `policy-alone-is-a-lead` | no `auth-policy` case reaches `impact-proven` without a chain edge to `ato` |
| `surface-gate` | distinct `(field, surface)` pairs are counted; one surface does not clear the others |
| `no-credential-literals` | `authpolicy.py` contains no password, OTP or token literals |
| `owned-accounts-only` | every case references an account declared in `scope.json` |

The `policy-alone-is-a-lead` eval encodes `hunt-auth-bypass:155-158` as a test. It is
the point of the class: these observations are chain sources, and the engine should
refuse to let one be reported on its own.

---

## 16. Original build order and current limits

1. **`declared_constraints` in `fields.py`** (§5) with the `source` distinction. Pure
   offline schema plus a reader; useful to every class immediately.
2. **The `matrix()` surface gate** (§11). Also offline, and it closes the operator's
   per-field principle at the surface level.
3. **`recon/authpolicy.py`** schema, cases, `sync` from `AUTH_PATH`. No traffic.
4. **`sample` + `derive`** (§8). Offline derivation over collected samples.
5. **The skill**, plus catalog and skillmap, landed together.
6. **Chain edges** (§10), including `ap-logout-noop` as a post-condition on ATO chains.
7. **Entry-point policy cases** (§6) — the first cases that send anything.
8. **Invalidation cases** (§7), ending with the post-logout replay.
9. **Rate-limit cases** (§9), last, because they are the only ones that deliberately
   provoke a control response.

The offline constraints, declared render gate, exact auth-case inventory and
metadata-only derivation are implemented; none sends traffic. A sample shape is
**not findings-grade** or a prediction. Steps requiring live attempts, an
independent validator or a connected executor remain unimplemented and need the
campaign's written scope and grants.

---

## Sources

- `.claude/skills/hunt-auth-bypass/SKILL.md:155-158` — the "Not bugs on their own"
  doctrine this plan mechanises; `:59`, `:68`, `:163-165`
- `.claude/skills/hunt-ato/SKILL.md:36`, `:63`, `:66` — reset-token coverage already
  installed
- `.claude/skills/hunt-mfa-bypass/SKILL.md:48-61`, `:88` — OTP and backup-code coverage
- `recon/fields.py:56` (field_cases key), `:65-75` (canary surface tracking), `matrix()`
- `recon/score.py` — `AUTH_PATH`, the seeding source
- `recon/factcheck.py:19-22` — the four predicates and the no-negation constraint
- `recon/findings.py` — `CHAIN_HINTS`, and the 12-orphan chain audit
- `vault/_data/reports-merged.csv` — 863 `auth-bypass` rows against 16 `ato` and 0
  `mfa-bypass`
- Operator techniques, this session: frontend weak password, Burp-intercept constraint
  swap, forgot/reset policy gap, old-link invalidation, identifier patterns, and the
  logout back-button test
