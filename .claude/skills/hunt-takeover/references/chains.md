# Conditional trust edges and investigation priority

Review trust **before claiming**, using stored responses and artifacts only. Bind
each edge to the exact hostname/origin, source page/operation, capture time,
response/artifact/hash and account/role/tenant/workflow when available. Separate
current production evidence from an archived or synthetic reference. A guessed
hostname match or a source-map string alone is not an active trust policy.

## Priority is not impact, readiness or severity

A currently referenced stale hostname often deserves investigation before an
isolated dangle. Show both axes: **why it matters if controlled** and **what blocks
proving control now**. Historical provider status, missing referrals, wildcard
ambiguity, absent namespace evidence, grants, transport or cleanup keep the branch
blocked even when it ranks first. Prefer the least intrusive ready step: offline
source review or a dossier request, not an automatic claim. Never turn several
conditional edges into several confirmed findings.

## Chain preconditions and proof

| Edge | Captured evidence supports | Missing link before impact can be claimed |
|---|---|---|
| CSP script source | The effective enforcing policy may admit scripts from this host | An actual script load/injection mechanism plus browser execution in the protected origin, replay and distinct control. An allowlist **does not create an injection point**. |
| Domain cookie | Some cookies may be eligible for delivery to the controlled host, or a sibling might attempt cookie-setting interference | Actual browser delivery or parent application acceptance on owned test sessions, cookie semantics, TLS and separate downstream state. No automatic session theft/fixation. |
| CORS | A captured response advertises an allowed origin/credentials policy | Exact controlled origin, browser credential delivery, sensitive owned-account response and browser-readable result; compare denied origin/control. No inference from headers alone. |
| OAuth redirect | A captured configuration or flow references this URI | Server-side redirect acceptance and real owned-account flow with state/nonce/PKCE/audience checks; approved code exchange and resulting session before ATO. A query parameter or JS constant is not an allowlist. |
| Same-site/CSRF | Sibling control may change request context | Browser site calculation, cookies actually sent, a state-changing owned action and missing defense, with a distinct control. Same-site is not same-origin. |
| MX/SPF/DKIM | A mail-routing or authentication dependency exists | Exact provider/DNS control plus a separately approved owned-mailbox test and applicable mail-policy evaluation. No interception, spoofing or password-reset proof from records alone. |
| NS | A delegated subtree might rely on the suspect authority | Parent delegation, authoritative/other-server behavior, namespace/control path and resolver effects. One broken NS does not grant the whole parent zone. |
| HSTS | A host/subtree may require HTTPS in supporting browsers | Usable exact-host trusted TLS and the target chain's own proof. HSTS is a transport constraint, not a trust grant, ownership or certificate-validity fact. |

## Exact-host and browser semantics

### Cookies and public suffixes

Apply domain matching at label boundaries: a host equals the cookie domain or ends
in `.` plus that domain; a substring is insufficient. A leading dot on `Domain`
does not mean an arbitrary wildcard and has no modern semantic advantage. No
`Domain` means host-only: a parent host's host-only cookie does not reach siblings.
Preserve source host, explicit Domain presence, Path, Secure, HttpOnly, SameSite and
prefixes without retaining cookie values. Path affects delivery but is not a robust
security boundary. HttpOnly blocks script reads, not eligible network delivery;
Secure requires suitable transport. `__Host-` requires Secure, Path=/ and no Domain
in supporting browsers, so do not treat it as a parent-domain cookie.

Browser rejection of cookies on a **public suffix** and SameSite's schemeful site
calculation require a current PSL/browser context. Do not guess eTLD+1 from the last
two labels, infer a multi-tenant provider's registrable domain from its suffix, or
label every sibling same-site. DNS record matching can be checked directly without
pretending the local model implements full PSL/browser policy. When unavailable,
record `PSL/site-policy unknown` and require approved browser evidence for the chain.
Cookie access does not establish the app accepts a session or that fixation works;
test only supplied owned sessions and never collect real users' cookies.

### CSP

Keep scheme, host, wildcard semantics, port and path distinct. Determine the
applicable effective directive/fallback; `script-src-elem`, nonces/hashes,
`strict-dynamic`, multiple enforcing policies and browser behavior can change whether
a host source is useful. Report-only policy does not allow/block execution. A
policy allowing an origin does not show a page ever loads from it, that input can
create a load or that any attacker-controlled script executes. An absent CSP is
likewise not evidence of injection. Hand an actual render/load surface to `hunt-xss`.

### CORS and OAuth

Use exact serialized origins (scheme, host, port), not hostname substring or a
guessed regex. `Access-Control-Allow-Origin: *` is not permission for browser
credentialed reads; `Allow-Credentials: true` alone is insufficient. Credentials,
preflight, response sensitivity and browser readback remain independent. A static
response does not reveal the complete dynamic allowlist.

OAuth references need a real authorized flow. Do not redeem another person's code
or token; use A/V-owned test identities only. A redirect reaching a controlled
origin still need not yield a usable code/session because of client binding, PKCE,
state and flow-specific defenses. Keep takeover control proof separate from OAuth
or account takeover proof and record the exact shared lineage.

### Mail and authority

SPF `include` resolution failure may cause an error rather than authenticate mail.
DKIM DNS ordinarily publishes a public key, not a signing secret; one selector does
not represent every sender. MX routing, DKIM, SPF and DMARC alignment differ and
must not be merged into "brand mail owned." Do not send mail or listen for real
messages under this offline skill. NS impact is constrained by the delegated
subtree, surviving servers, caches, DNSSEC and actual provider control.

## Handoffs and reporting

Route proven effects to the class owner (`hunt-xss`, `hunt-oauth`, `hunt-ato`,
`hunt-csrf`, `hunt-access-control`) with one root-cause lineage and each class's
replay/control requirements. Mail work remains blocked without its own explicit
approval and safe owned test path; no mail implementation is supplied here.
The validator chooses reportability and severity from demonstrated gain, blast
radius and fix, not the number of trust edges or DNS record type. If the program
accepts dangling-DNS-only reports, cite that exact rule and report the limited
observation honestly rather than upgrading it to a demonstrated chain.
