# Burp handoff: OTP races and out-of-band callbacks

Status (2026-11-12): **Burp MCP connected; active testing remains an operator workflow,
not a campaign-enforced BugVault executor**. The live loopback service identifies as
`burp-suite` 1.1.2 and advertises 27 tools. OpenCode's project MCP is connected;
native Claude Code's project entry awaits the user's project approval. Tool discovery
does not verify a licence, successful callback or successful race. All skill guidance
stays inside BugVault's single `.claude/skills/` folder.

## Shared MCP data access (all tool-capable models)

`opencode.json` registers `burp` at `http://127.0.0.1:9876/mcp` for this project,
independent of the selected provider/model. `.mcp.json` registers the same endpoint
for native Claude Code; approve it in `claude` when prompted. Other clients must load
this server explicitly. The service is loopback-only and needs Burp left running.
The copied JAR at `tools/burp/mcp-proxy.jar` is optional for stdio-only clients; no
client configuration depends on the original download. See `tools/burp/README.md`.

Available live data tools: `get_proxy_http_history`, `get_proxy_http_history_regex`,
`get_proxy_websocket_history`, `get_proxy_websocket_history_regex`, `get_organizer_items`,
`get_organizer_items_regex`, `get_scanner_issues` and `get_active_editor_contents`.
Use bounded `count`/`offset` pages and campaign-relevant filters. `output_project_options`
and `output_user_options` also expose config, but may contain secrets and need review.
OpenCode prefixes tool names with `burp_`. The same permissions apply regardless of
model; read access does not mean broadcasting all raw traffic to all providers.
Private program data and credentials need minimization/provider approval. Save relevant
evidence in the campaign so another model/session can resume without conversation memory.

The service also exposes `create_repeater_tab`, `create_repeater_tab_http2`,
`send_to_intruder`, `send_http1_request`, `send_http2_request`,
`generate_collaborator_payload` and `get_collaborator_interactions`. These active,
preparatory or externally polling actions require operator approval. They are not
connected to recon scope, budgets, pacing or stored response IDs. No exposed tool
sends a synchronized Repeater group or runs/controls an Intruder attack. Do not infer
these capabilities from the presence of a tab-creation tool.

## Choose the right tool

| Need | Tool | What it does not establish |
|---|---|---|
| Small, rate-controlled request variants | Intruder with a finite list and resource-pool limits | Concurrent requests are not synchronized race requests |
| OTP state-transition race | Repeater: **Send group in parallel** | Two successes do not by themselves prove an MFA bypass |
| DNS/HTTP callback detection | Collaborator (Burp Pro), or an approved operator-controlled listener | A callback alone is not file disclosure, key trust or account takeover |
| Callback payloads in Intruder | Intruder's Collaborator payload type (Pro) | Intruder still needs the Collaborator service; save its attack results |
| `jku` / `x5u` key-trust proof | Controlled HTTPS JWKS / certificate endpoint | Collaborator's default response does not serve your chosen key |

## Authorization and execution boundary

- Check exact URLs with `python3 -m recon check <campaign> <url>`, review exclusions,
  and keep methods inside `policy.allowed_methods`. A method advertised by OPTIONS
  does not extend permission. Burp scope settings are not an egress firewall.
- Generated hunter/validator/reporter briefs use `recon send` for target requests.
  They may read relevant Burp evidence through MCP or prepare a textual handoff, but
  do not grant HTTP sends, tab/Intruder preparation, settings changes, Collaborator
  generation/polling or routing the scoped client through Burp. Those need an explicit
  operator-approved action. Never use Burp after a policy/budget/scope failure.
- The human operator needs permission for the particular test. A synchronized burst
  needs an explicit burst allowance; do not override `max_rps` or treat an average
  rate as permission for simultaneous requests. Without it, park the race.
- Before any external run, record the written authorization, allowed host/port/path,
  method, A/V account labels, disposable resource IDs, start/stop time, request cap,
  concurrency/burst cap, delay and stop conditions in the campaign's private `.recon/`.
  Pause other campaign traffic. Reserve headroom manually for **all** external
  requests (including preparation, retries, redirects and controls) against the
  campaign total, and reconcile actual counts before resuming. BugVault does not
  reserve or count these requests automatically. If that accounting cannot be
  maintained, do not run externally.
- Disable unneeded scanners, extensions, automatic redirects, retries and login
  macros. Verify target destination on each prepared request. Stop at lockout,
  CAPTCHA, 429, unexpected side effects or the recorded cap; already-sent requests
  in a parallel batch cannot be recalled. Never rotate IPs or use real users.
- Approve the callback service separately: it may receive target metadata. Prefer a
  private service when program rules forbid third-party evidence storage. Do not put
  credentials, reset tokens, private files or personal data in a callback URL.

## OTP race: operator workflow

1. Use A's account and a disposable MFA challenge. Establish the sequential control
   first: one use succeeds; repeating the same one-time operation is rejected, or
   the documented state transition is enforced. Save requests, responses and state.
2. Obtain a fresh equivalent challenge. Start with **two** prepared requests using
   a known test code, not a list of guesses. This tests state reuse/atomicity; it does
   not prove an unknown OTP can be bypassed. Keep host, port and transport identical.
3. Put them in a Repeater group, select **Send group in parallel**, and obey the
   recorded burst allowance. Repeater uses last-byte synchronization for HTTP/1 and
   single-packet synchronization for HTTP/2+. Meet the installed version's parallel
   prerequisites; avoid session macros that disturb synchronization.
4. Save exact bytes, timestamps, HTTP version, synchronization mode, request count,
   response ordering, and independently verified post-MFA session state. Compare
   against the sequential control; do not infer a security boundary from status
   codes alone. Challenge freshness and shared session locks can confound results.
5. If the feature is unavailable or scheduling remains uncertain, Intruder can show
   only unsynchronized concurrency. Do not call a negative result race-free. Park
   it pending a reviewed Turbo Intruder workflow or native synchronized executor;
   neither is installed or implemented by this change.

For ordinary bounded OTP rate checks, use `recon send` one request at a time. A human
using Intruder must use a fixed list of at most 25 wrong attempts (or the program's
lower cap), one concurrent request and the required delay. Finite acceptance shows
only that no limit was observed at that count, not unlimited guesses.

## Callbacks: operator workflow

1. In Collaborator (Pro), generate one unique payload ID per test and separate IDs for
   controls. Keep polling secrets private. Do not visit the payload URL yourself.
2. Submit the in-scope target request through `recon send` where possible; the callback
   hostname is payload data, not a new host BugVault may probe. Record the resulting
   `request_id`, payload ID, request/body hash and timestamp locally.
3. Poll in Collaborator, then export interactions and raw request details. If Intruder
   inserted the Collaborator payload, its interactions appear in that attack's results;
   save the attack, not just the standalone Collaborator tab. No direct Intruder
   execution is needed when `recon send` can submit the request.
4. Correlate the payload ID, time, protocol and originating source with the initiating
   request and control. Distinguish application traffic from a browser, DNS resolver,
   scanner, proxy or analyst action. A callback supports only the observed interaction;
   DNS alone does not prove HTTP retrieval or a completed XXE/authentication chain.
5. For `jku`, serve a deliberately chosen public JWKS on approved HTTPS; for `x5u`,
   serve the intended public certificate chain. Log the retrieval, then prove the
   forged token actually returns V's marker and compare a rejected-token control.
   A generic Collaborator callback proves neither usable content nor trusted keys.
6. Without Pro, use an approved operator-controlled DNS/HTTPS listener with unique
   correlation IDs, timestamps and private logs. If none is allowed/reachable, park
   the lead. No listener is deployed or made public automatically.

## Evidence back into BugVault

Keep raw Burp exports and callback logs under the campaign's private `.recon/` folder.
Create a normal `finding add` lead with the external artifact paths and measured
limits in `--note`. HAR import is **surface/context only**: it does not import raw
request bodies, grant a stored response ID, prove an OTP race or validate callbacks.
`fact check` can check only stored `recon send` responses, not an external Burp ID or
a callback CSV. The validator must inspect the original external artifacts and the
distinct replay/control evidence before advancing the finding. Preserve inconclusive
evidence as a parked lead; apply the existing reportability gate without bypasses.

## If manual tools do not work: implementation plan (not built)

1. Define campaign-bound external-execution approval: immutable scope/method snapshot,
   expiry, explicit burst cap, callback-provider approval and kill switch. A free-form
   boolean or tool installation is not enough.
2. Add atomic budget reservations shared with native requests, bounded concurrency,
   no redirect/retry escape, validated DNS/IP egress and cancellation. Do not simply
   remove `host_pacing`; synchronized bursts need separately approved policy.
3. Build a reviewed Burp extension/bridge or native burst executor. Verify installed
   Burp edition/version and synchronization support; fail closed on absent approval,
   stale scope, unknown destination, oversized batch or exhausted budgets.
4. Add a pluggable Collaborator/private-listener connector: securely stored polling
   credentials, per-attempt correlation, time-bounded polling, deduplication, provenance
   and hashes of raw events. Retrieval checks and key-serving endpoints are different
   capabilities; never silently provision public infrastructure.
5. Add an external-evidence adapter that keeps the source label (Burp vs native), exact
   bytes/timing and controls without auto-confirming findings or fabricating native
   response IDs. Keep current finding/reportability gates.
6. Before enabling an agent, pass owned-lab tests: method/scope/redirect denials,
   shared-budget exhaustion across processes, burst caps and cancellation, a known
   atomic vs non-atomic OTP fixture, fake/duplicate/delayed callbacks, benign JWKS
   retrieval vs actual key acceptance, and negative controls. Then run a supervised
   authorized pilot. Until then the catalog remains **manual-only**.

## Vendor references (checked 2026-11-12)

- [Repeater group send and synchronization](https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group)
- [Collaborator, Intruder payloads and exporting interactions](https://portswigger.net/burp/documentation/desktop/tools/collaborator)
