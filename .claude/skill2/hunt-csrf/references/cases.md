# hunt-csrf case catalogue

Generated from `recon/csrf.py` `CASES` (the engine and this page cannot drift: a
test compares them). Each case is worked per context; each variant is one attempt,
recorded with `python3 -m recon csrf record ... --case <case> --variant <variant>`.
"Applies when" is evaluated per context by the ledger and shown with its reason in
`recon csrf plan`; an inapplicable variant shows as `n-a-suggested`.

## `baseline` — Action authority baseline

- **Applies when:** always
- **Initial hint:** captured or declared state-changing action
- **Tools:** dedicated browser + DevTools; Burp history
- **Reopened by changes to:** shape, tokens

| Variant | Applies when | Technique |
|---|---|---|
| `legit-request` | always | capture the legitimate same-origin request exactly as the app emits it: method, MIME, every token channel, which credentials ride along |
| `state-readback` | always | fix an independent before/after readback of the owned state or identity this action changes (a response status is not a readback) |
| `delivery-mode` | always | note how the app sends it (form, navigation, fetch/XHR, WebSocket message) and from which page |

## `token-enforcement` — Token enforcement across every accepted channel

- **Applies when:** an ambient credential (cookie or browser-managed auth)
- **Initial hint:** form field, header or interceptor carrying an anti-CSRF token
- **Tools:** source/interceptor review; Burp Repeater as a diagnostic; browser for the real attempt
- **Reopened by changes to:** tokens, shape, headers

| Variant | Applies when | Technique |
|---|---|---|
| `omit-all-channels` | always | the request with no token in any channel; a token left in a second channel still validates, so remove every copy at once |
| `empty-value` | a captured anti-CSRF token channel | parameter or header present but empty |
| `invalid-value` | a captured anti-CSRF token channel | same-format, same-length value that was never issued |
| `alternate-channel` | a captured anti-CSRF token channel | token moved to another channel the server reads (body, query, header) or the expected channel dropped while another stays |
| `duplicate-precedence` | a captured anti-CSRF token channel | repeated parameter / query-vs-body copies: which one the validator reads versus which one the handler uses |

## `token-context` — Token binding, lifecycle and transport

- **Applies when:** a captured anti-CSRF token channel
- **Initial hint:** identified token design (synchronizer, masked, signed, double-submit, custom header)
- **Tools:** two supplied accounts in separate browser contexts; Burp Repeater comparisons
- **Reopened by changes to:** tokens

| Variant | Applies when | Technique |
|---|---|---|
| `cross-session` | a captured anti-CSRF token channel | token issued to another session of the same test account |
| `cross-account` | a captured anti-CSRF token channel | token issued to the other supplied account used with this account's session |
| `lifecycle` | a captured anti-CSRF token channel | token across logout/login, renewal and expiry; a stable per-session token is a valid design, so test the transitions rather than the stability |
| `leak-surface` | a captured anti-CSRF token channel | where the token is readable by another origin: URL/query, Referer, cached page, error page, JS-readable endpoint |

## `cookie-binding` — Double-submit and cookie-paired tokens

- **Applies when:** a CSRF-named cookie next to the token
- **Initial hint:** a CSRF-named cookie next to a submitted token
- **Tools:** DevTools cookie inspector; framework documentation for the pairing design
- **Reopened by changes to:** tokens, cookies

| Variant | Applies when | Technique |
|---|---|---|
| `pair-design` | a CSRF-named cookie next to the token | classify the pair: naive equality, signed/HMAC, or bound to the session |
| `pair-mismatch` | a CSRF-named cookie next to the token | cookie and submitted value from different issuances |
| `cookie-planting` | a CSRF-named cookie next to the token | with an established cookie-setting primitive (sibling Set-Cookie, header injection): plant a matching pair while the victim's session stays the victim's |

## `origin-metadata` — Origin, Referer and Fetch Metadata checks

- **Applies when:** an ambient credential (cookie or browser-managed auth)
- **Initial hint:** server checks Origin/Referer/Sec-Fetch-* instead of, or next to, a token
- **Tools:** dedicated browser + DevTools; Burp to read the emitted headers
- **Reopened by changes to:** origin, cookies, headers

| Variant | Applies when | Technique |
|---|---|---|
| `cross-site-origin` | always | a browser-emitted cross-site Origin from the recorded initiator page |
| `absent-referer` | always | Referer suppressed by referrer policy on the initiator; record Origin and Referer separately |
| `null-origin` | always | opaque origin from a sandboxed frame or data: document |
| `lookalike-origin` | always | registrable lookalike host that defeats prefix, suffix or substring allowlists |
| `sibling-origin` | always | same-site sibling initiator against a check that trusts the whole site |
| `fetch-metadata` | always | Sec-Fetch-Site/Mode/Dest enforcement and its missing-header fallback |
| `redirect-hop` | always | initiation through a redirect on a trusted origin and which metadata survives the hop |

## `cookie-delivery` — Session cookie delivery by site relationship

- **Applies when:** an ambient credential (cookie or browser-managed auth)
- **Initial hint:** ambient session cookie and its SameSite/Domain/Path attributes
- **Tools:** dedicated browser on the recorded build; DevTools cookie and network panels
- **Reopened by changes to:** cookies

| Variant | Applies when | Technique |
|---|---|---|
| `top-level-get` | a GET action | cross-site top-level GET navigation (Lax cookies still attach) |
| `top-level-post` | a non-GET action | cross-site top-level form POST |
| `subresource-frame` | always | image/script/iframe-embedded request |
| `credentialed-fetch` | always | fetch/XHR with credentials included, as a simple request |
| `same-site-sibling` | always | initiation from a same-site sibling origin; requires control of that origin |
| `default-lax-age` | a captured cookie without explicit SameSite | cookie without SameSite: fresh versus aged behaviour on the recorded browser build |
| `redirect-method-change` | always | a POST that becomes a GET through a 302/303 chain |

## `representation` — Body representation and preflight

- **Applies when:** a body-carrying method
- **Initial hint:** JSON, multipart or API action with a request body
- **Tools:** browser forms/fetch; DevTools for the preflight and the actual request
- **Reopened by changes to:** shape

| Variant | Applies when | Technique |
|---|---|---|
| `form-urlencoded` | a body that is not urlencoded | same operation as application/x-www-form-urlencoded |
| `multipart` | a body that is not multipart | same operation as browser-built multipart/form-data |
| `text-plain` | always | text/plain body, JSON-shaped when the parser is lenient |
| `content-type-parameters` | always | parser leniency on MIME parameters, charset and casing that a browser can actually emit |
| `preflight-path` | a non-simple MIME or custom header | non-simple request: the preflight decision and the actual request recorded separately; an unreadable response can still be a delivered write |

## `middleware-coverage` — Methods, routes and middleware coverage

- **Applies when:** an ambient credential (cookie or browser-managed auth)
- **Initial hint:** alternate method, version or handler for the same action
- **Tools:** import ledger and route inventory; Burp Repeater; browser for the effective request
- **Reopened by changes to:** shape

| Variant | Applies when | Technique |
|---|---|---|
| `get-mutation` | a non-GET action | the same state change through GET with query parameters |
| `override-parameter` | PUT/PATCH/DELETE | _method-style override sent as a form/query parameter from a POST form |
| `path-variant` | always | trailing slash, case, encoding and normalization of the protected route |
| `legacy-version` | always | older API version or alternate handler serving the same action |
| `exempt-route` | always | route prefixes or handlers excluded from the CSRF middleware |

## `graphql-operation` — GraphQL operation transport

- **Applies when:** a GraphQL endpoint
- **Initial hint:** GraphQL endpoint or client document naming a mutation
- **Tools:** JS/capture review of operation documents; browser
- **Reopened by changes to:** shape

| Variant | Applies when | Technique |
|---|---|---|
| `get-transport` | always | the selected mutation sent as GET query parameters |
| `simple-body-transport` | always | urlencoded, multipart or text/plain POST bodies the server still parses as GraphQL |
| `batch-alias` | always | batched or aliased operations carrying the mutation |
| `persisted-query` | always | persisted/hash-identified invocation of the operation |

## `client-input-request` — Client-side CSRF through the app's request builder

- **Applies when:** a JS client / SPA source
- **Initial hint:** SPA/JS client that builds authenticated requests from URL, hash or messages
- **Tools:** static JS tracing; DevTools initiator/call-stack view
- **Reopened by changes to:** shape

| Variant | Applies when | Technique |
|---|---|---|
| `url-param-sink` | always | query parameter steering the URL, method or body of an authenticated request the app sends itself |
| `hash-route-sink` | always | fragment or client-route state steering a request |
| `postmessage-sink` | always | postMessage data reaching a request builder without an origin check |
| `path-traversal-sink` | always | attacker-controlled path segment resolving to a different API route |

## `identity-transaction` — Login, linking and SSO transactions

- **Applies when:** a login/link/OAuth/SSO route
- **Initial hint:** login, logout, link/connect, OAuth/OIDC callback
- **Tools:** separate browser contexts for the two supplied identities; auth captures
- **Reopened by changes to:** tokens, shape

| Variant | Applies when | Technique |
|---|---|---|
| `login-csrf` | a login/session route | force the victim browser into the attacker's account |
| `link-callback-swap` | a link/connect/callback route | attacker-started link/connect callback completed inside the victim's session |
| `state-binding` | an OAuth/OIDC/SSO route | state, PKCE and nonce bound to the initiating browser session and transaction, evaluated together |
| `error-path-disclosure` | an OAuth/OIDC/SSO route | state or code exposed on error and retry paths |

## `saml-transaction` — SAML response correlation

- **Applies when:** a SAML route
- **Initial hint:** SAML SP/ACS flow
- **Tools:** browser SAML capture; hunt-saml for signature/parser work
- **Reopened by changes to:** shape

| Variant | Applies when | Technique |
|---|---|---|
| `unsolicited-response` | always | IdP-initiated response accepted without a matching request where the SP should require one |
| `inresponseto-binding` | always | InResponseTo bound to the browser session that started the flow |
| `relaystate-binding` | always | RelayState treated as transaction state, not only as a redirect target |
| `response-replay` | always | an already consumed assertion replayed |

## `realtime-authority` — WebSocket and SignalR action authority

- **Applies when:** a realtime endpoint
- **Initial hint:** WebSocket/SignalR/Socket.IO endpoint
- **Tools:** browser + Burp WebSocket history; DevTools frames
- **Reopened by changes to:** headers, cookies

| Variant | Applies when | Technique |
|---|---|---|
| `handshake-origin` | always | cross-site handshake: Origin validation on upgrade or negotiate |
| `cookie-handshake` | always | ambient cookie authenticating the connection |
| `message-authorization` | always | a protected message or action executed over the cross-site connection (a 101 alone only switches protocols) |
| `transport-fallback` | always | negotiate, SSE and long-polling transports enforcing the same checks |

## `bff-protection` — Backend-for-frontend header protection

- **Applies when:** a constant custom header or /bff route
- **Initial hint:** constant custom header (e.g. X-CSRF: 1) or a /bff route family
- **Tools:** browser fetch with and without the header; DevTools preflight
- **Reopened by changes to:** headers, cookies

| Variant | Applies when | Technique |
|---|---|---|
| `required-header` | always | required constant header plus restrictive CORS: a valid defense when enforced, so confirm enforcement rather than assume a bypass |
| `excluded-route` | always | routes or hubs excluded from the header requirement |
| `cors-policy` | always | a preflight policy that would admit the header cross-origin |
| `cookie-scope` | always | session cookie Domain widened beyond the host |

## `effect-handoff` — Effect chains and restoration

- **Applies when:** always
- **Initial hint:** a demonstrated action in this context
- **Tools:** findings/chain ledger; hunt-ato, hunt-xss, hunt-oauth, hunt-ssrf handoffs
- **Reopened by changes to:** nothing (follows the other cases)

| Variant | Applies when | Technique |
|---|---|---|
| `ato-chain` | always | email/password/MFA/link change carried through to account access on the supplied victim account |
| `privilege-chain` | always | role, invite or permission change exercised |
| `integration-chain` | always | webhook, integration or API-key change exercised; a server-side fetch that follows goes to hunt-ssrf |
| `token-theft-chain` | always | same-origin script or XSS-read token driving the action; hand off to hunt-xss |
| `state-restore` | always | owned state restored after the demonstration |
