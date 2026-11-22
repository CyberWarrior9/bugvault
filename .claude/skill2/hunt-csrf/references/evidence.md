# hunt-csrf record bundle

`python3 -m recon csrf record` appends one event to a context's case history. Events are
append-only; artifacts are copied by SHA-256 into the campaign's private
`.recon/csrf-evidence/` store and re-hashed by `recon csrf verify`. Nothing is sent and
no finding is promoted.

## Fields

| Flag | Values | Meaning |
|---|---|---|
| `--context` | context ID from `csrf plan` | one action on one origin under one representation/authority/account/role/tenant/workflow |
| `--case` | a case ID from [cases.md](cases.md) | the family being worked |
| `--variant` | a variant ID of that case | one attempt shape; omit for a case-level outcome |
| `--state` | `attempted`, `observed`, `negative`, `blocked`, `inconclusive`, `n-a` | what happened |
| `--attempt-kind` | `browser`, `replay`, `review` | the dedicated browser built the request; Burp Repeater/native replay (diagnostic); source or configuration review |
| `--initiator` | `same-origin`, `same-site`, `cross-site`, `opaque`, `none` | relationship of the initiating page to the target origin; `none` for replays and reviews |
| `--initiator-origin` | `scheme://host[:port]` or `null` | the page that initiated the request; `null` for an opaque (sandboxed/data:) origin |
| `--delivery` | `form-post`, `form-get`, `navigation`, `subresource`, `iframe`, `fetch`, `websocket`, `redirect`, `client-script` | how the browser sent it |
| `--preflight` | `none`, `allowed`, `denied`, `unknown` | the CORS preflight decision, recorded separately from the actual request |
| `--browser` | engine/build label | cookie defaults differ by build; always record it for browser attempts |
| `--prerequisite` | free text | how a same-site initiator origin is controlled, or another prerequisite reference (finding id) |
| `--artifact` | `ROLE=PATH` (campaign-relative) | see roles below; at most eight |
| `--tool-ref` | e.g. `burp-history:5521` | external tool item IDs; never native `fact check` response IDs |
| `--requests` / `--connections` / `--messages` | counts | traffic the attempt produced (HTTP requests incl. preflights and readbacks, WS connections, WS messages) |
| `--note` | text | what was exercised and what the readback showed |

## Artifact roles

| Role | Content |
|---|---|
| `before` | state readback before the attempt (profile JSON, settings page, linked identities) |
| `after` | the same readback after the attempt |
| `request` | the request as the browser emitted it (DevTools/Burp export): cookies attached or not, Origin/Referer/Sec-Fetch, body bytes |
| `response` | the response to the attempt (often a 200 error page, a 204 or an opaque response) |
| `messages` | the WebSocket/SignalR frames of a realtime attempt |
| `initiator-page` | the HTML/JS hosted on the initiator origin |
| `preflight` | the OPTIONS exchange |
| `sibling-control` | how the same-site initiator origin is controlled |
| `trace` | client-side call stack or source trace (client-input-request) |

## Engine rules (design decisions encoded in `recon/csrf.py`)

- `observed` compares two **readbacks**: `before` and `after` must differ. A response
  status or body is not a readback of state.
- Attack cases are recorded after the context's `baseline` is observed.
- An `observed` attack case is a browser attempt from a different origin with its
  `request` artifact and delivery mode. The initiator origin equal to the target origin
  is the application itself and is refused.
- Replays and reviews carry initiator `none`: a forged Origin or Cookie header shows the
  server's policy, not what a browser sends.
- A `denied` preflight means the actual request never left the browser, so that variant
  is `negative`, not `observed`.
- A same-site initiator (declared, or computed from the origins) needs `--prerequisite`.
- `realtime-authority` observations include the `messages` artifact: a 101 handshake only
  switches protocols.
- A case-level `negative` is accepted once every applicable variant has an event (or is
  recorded `n-a` with a reason); `n-a`, `blocked` and `inconclusive` carry a note.
- The site relationship is computed with a heuristic registrable domain (last two
  labels, common ccTLD second levels), not a Public Suffix List lookup; a mismatch with
  the declared initiator is flagged `relationship_conflict`, never silently rewritten.
- Each event stores the context's facet hashes (tokens, headers, cookies, origin,
  shape). A later capture that changes a facet marks only the cases depending on it as
  stale; the event stays in history.

## Examples

```bash
# server-side diagnostic: which channel does the validator read?
python3 -m recon csrf record acme --context 12 --case token-enforcement \
  --variant alternate-channel --state attempted --attempt-kind replay --initiator none \
  --tool-ref burp-repeater:88 --requests 2 --artifact response=evidence/csrf/12-repeater.txt \
  --note "header token removed, body token kept: still accepted (second channel validates)"

# browser attempt that the server rejected, state unchanged
python3 -m recon csrf record acme --context 12 --case token-enforcement \
  --variant omit-all-channels --state negative --initiator cross-site \
  --initiator-origin https://attacker-lab.example --delivery form-post --browser "Chrome 131" \
  --artifact before=evidence/csrf/12-before.json --artifact response=evidence/csrf/12-403.html \
  --note "no token in any channel: 403, readback unchanged"

# realtime: protected message executed over a cross-site connection
python3 -m recon csrf record acme --context 31 --case realtime-authority \
  --variant message-authorization --state observed --initiator cross-site \
  --initiator-origin https://attacker-lab.example --delivery websocket --browser "Chrome 131" \
  --connections 1 --messages 3 --artifact before=evidence/csrf/31-before.json \
  --artifact after=evidence/csrf/31-after.json --artifact request=evidence/csrf/31-handshake.txt \
  --artifact messages=evidence/csrf/31-frames.json
```
