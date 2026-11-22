---
name: hunt-xss
description: "XSS and HTML-injection hunting for authorized BugVault campaigns: reflected, stored, DOM and blind/mutation variants across every input field (query, body, path, header, cookie, JSON, GraphQL), with a per-field context map (HTML body, attribute, JS string, template, URL), a probe-ladder method for mapping exactly how a WAF/filter detects and rewrites payloads before designing a context-fit variant, and chain targets (admin-panel session theft, ATO, CSRF bypass). Use for every coverage row of class xss and whenever an input value re-appears in HTML, attributes or client script."
license: "MIT; original BugVault workflow"
metadata:
  implementation: "recon inputs census + fields ledger/canary/matrix/packet; recon waf profiles; recon send executor; recon fact check for marker proofs"
  reviewed: "2026-11-13"
---

# Hunt: XSS / HTML injection

An XSS is an input landing in an execution context un-encoded. Two things decide
everything: **which field** and **which context**. Payload lists don't find XSS;
per-field context mapping does — a breaker for a JS string dies inside an HTML
attribute, and the perfect attribute breaker is inert in a template literal.

## When this skill applies

- `coverage.md` rows of class `xss` (`recon/score.py` seeds them for every
  parameterized endpoint).
- Any observed input whose value re-appears in page HTML, an attribute, client
  script, an error page, a JSON field rendered client-side, or a file name /
  header value reflected in a listing.
- Profile-style fields (first/last name, username, display name, bio, address,
  nickname, title, comment, status message) — classic stored-XSS carriers.
- DOM code reading `location`, `postMessage`, `document.referrer`, storage,
  `name`, or JSONP into sinks.

## Step 1 — the input census and the field ledger (why fields don't get skipped)

Run `python3 -m recon inputs <campaign> --asset-id N`. It merges every observed
input name with its locations (query/body/header/cookie/path), methods, accounts,
ID-likeness, **stored-probe receipts** (`probe_seen_in_requests`) and the field
ledger's per-case states. Seed the **field ledger** with
`python3 -m recon fields sync <campaign> --asset-id N`: one row per
field × location × account × case (reflected / stored / DOM / blind), state
`untested → probed → mapped → observed/negative/...`, recorded per row with
`recon fields record --state ...` (payload author goes in `--model`). No field
closes until it has a verdict or a recorded reason. Locations the engine cannot
see yet — headers, cookies, and fields only reachable through the UI — come from
`python3 -m recon import-burp <campaign> <burp-export>` (header/cookie **names**
only, values dropped) and page-standalone inputs harvested at mapping time.
Profile fields are exercised through their real save/preview/render workflows,
one field at a time.

Before any negative verdict, check the module's **trigger matrix**:
`recon fields matrix --module <family>` renders list/search/filter/create/edit/
bulk/export/sort cells — the same field often validates differently per workflow
shape, and second-order sinks hide in the shapes you did not capture. A module
with missing cells is `partial` by construction; `recon fields claim --state
full` is refused by the engine until every cell is captured or n-a with a reason.

## Step 2 — map the context before touching syntax

For each field, find every place the value lands and how:

| Context | What to identify | Breakout direction |
|---|---|---|
| HTML body text | surrounding tags; allowed tag set if a filter exists | new tag or event attribute |
| HTML attribute | quote style (`"`/`'`/none), attribute type (href/src/style/event) | close the attribute, then the tag; URL attributes may need `javascript:` or scheme tricks instead |
| JS string literal | quote, backtick, escaping of `\` and quotes | close the string, then inject an expression |
| JS template / JSON | `${}` interpolation, object context | interpolation or key breakout |
| URL/path reflection | decoding at each hop, `charset`, canonicalization | encoded payloads; path context may need `%2f` handling |
| Comment / CSS / SVG / markdown render | what the renderer permits | mXSS: crafted "safe" HTML that re-parses differently after mutation |

Record the context for **every render surface** of a stored value: the public
profile page, the admin user-list, emails, exports, mobile API views, and other
tenants' views. Stored XSS often executes only on the second surface. The
engine turns this into the **propagation map**: `recon fields canary --asset-id
N --field F` mints a per-field marker (`bv_` + 8 hex); submit it once through
the real workflow, then `recon fields trace --marker <M>` searches stored
captures for where the value landed (submission-capture / same-response /
other-endpoint / export-csv / export-pdf) and how it is encoded there.

## Step 3 — the probe ladder: map the detector, then design

Never fire a payload wordlist. Map what the defense actually does, one probe at
a time, each carrying a unique marker (`canary_xss_<8 rand>`). The engine
generates the ladder for you: `recon waf plan --host H` emits a bounded
single-then-pair probe sequence with unique markers; classify each response
with `recon waf observe` (status / challenge template / added edge headers /
reset / **silent-strip** = baseline-equal page with the element gone) or store
the outcome with `recon waf record --outcome allowed|blocked|stripped|modified|reset
--location query|json|form|multipart|header|path`. The per-host element table
feeds the payload design — do not start cold:

1. **Pure marker** (no syntax) — does it round-trip at all? Silent truncation,
   length caps and profanity filters show up here.
2. **Structure probes, one at a time** — `<`, `>`, `"`, `'`, backtick, `=`,
   parentheses, `/` — observe per character: passed through, HTML-encoded on
   output, URL-encoded, stripped, or request blocked.
3. **Classify the rule**: blocklist on tokens / output-encoding at specific
   contexts / input strip-and-rebuild / WAF page (HTTP 403 shape) / full
   parse-sanitize (e.g., markdown allowlist). Each has a distinct signature.
4. **Design the variant for the rule + context**, not for luck: for
   output-encoding in body text, switch context (attribute, JS, URL reflection)
   instead of fighting the encoder; for token blocklists, use the context's
   less-common equivalents (event handlers beyond `onerror`, SVG/Math
   namespaces, form/action, unclosed tags); for WAF pages, mismatch its parsing
   with the server's (case, encoding layers, comment splitting, tag whitespace,
   newline inside tags) — guided by which characters step 2 proved pass.
5. **Prove execution, not presence**: a marker that renders proves reflection;
  only the marker executing (or landing in a dangerous attribute) proves XSS.
  Use `fact check --response <id> --predicate body_contains_raw` to bind the
  marker claim to the stored response.

When the ladder and the propagation map are done, assemble the **payload
context packet**: `recon fields packet --asset-id N --field F --case C` returns
the field/location/context map, surviving characters and blocked elements (from
the WAF profile), DB fingerprint, CSP and method grants — and refuses to build
while any piece is missing. Design payloads from the packet; `recon fields
payload --file <packet.json> --model <model>` records who authored what.

## The four variants

- **Reflected**: same response. Check the error/404 pages and redirect bodies —
  under-tested surfaces.
- **Stored**: save once, then visit **every** render surface with the browser;
  the admin view is the money surface. Confirm cross-surface with a second
  test account where the field is visible to others.
- **DOM**: in the browser, trace source → sink: `location.hash/search`,
  `postMessage`, `document.referrer`, `name`, localStorage → `innerHTML`,
  `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout(string)`,
  jQuery `$()`/`.html()`, framework `v-html`-style bindings. Pass the marker
  through each source and observe which sink renders it. Framework escaping
  that "protects" one sink often does not protect a `href="{{user}}"` URL sink.
- **Blind**: the payload fires where you are not — support tickets, chat,
  profile fields shown only to staff, contact forms. Use your own second
  account or an operator-visible admin view as the observation surface; where
  the program supplies a callback host, bind a unique per-attempt marker exactly
  as `hunt-ssrf` does (host grant via `xss.callback_hosts`, falling back to
  `ssrf.callback_hosts`). Record the surface bundle with `recon fields blind
  --asset-id N --bundle <file>` — it validates marker binding, the approved
  callback host, the ≤24h window and evidence-vs-control distinctness on the
  same primitives as the SSRF correlator (`recon/callbacks.py`). A blind
  surface you cannot observe is `inconclusive`, not negative.

**HTML injection without JS execution is still a finding candidate**: injected
structure enables DOM phishing, CSRF-token theft and filter bypasses — record
it and check the chain table before discarding.

## Chains

| Surface | Chains into | Link |
|---|---|---|
| Stored XSS in an admin/staff view | session/token theft → ATO (`xss-admin-ato`) | `yields-access` |
| XSS on the OAuth redirect/callback page | authorization-code theft → ATO | `escalates-via` |
| Any XSS as the victim | CSRF bypass, email/password change → ATO | `enables` |
| XSS on a file-upload preview / filename | second-order stored XSS | `spawns` |
| HTML injection on a login page | credential phishing on the real domain (`htmli-token-ato`) | `enables` |

`recon chain status` ranks these once edges are proven — and a fully proven
chain still stays parked until the three realism questions
(`recon chain realism`) carry evidence-backed answers.

## Depth discipline and hard limits

- Ledger is per field × context × surface; the three-attempt rule applies per
  variant family, and "mapped the rule" (step 3) is what makes attempts
  genuinely different — three identical payloads prove nothing.
- Every payload carries a marker; marker execution is the only positive proof.
  Keep the plain-marker response as the negative-control baseline so encoding
  differences are attributable to your syntax, not the field. Negative
  verdicts name the encoding/rule observed.
- Test accounts only; never target real users with executing payloads. Never
  persist payloads beyond the proof session or deface shared surfaces — clean
  up your own test objects.
- Live tests originate in the dedicated browser through Burp; `recon send`
  only where the operator has excepted native checks; `fact check` binds
  response-marker claims to stored evidence.
