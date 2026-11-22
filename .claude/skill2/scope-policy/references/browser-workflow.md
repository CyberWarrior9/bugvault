# Dedicated visible browser and Burp proxy

Use one persistent **agent-only Chrome user-data directory** for approved login,
logout, signup, test-mailbox verification and browser-based target testing. Do not
use the person's normal profile, copy its cookies or sign in to Chrome sync.

## Prepared configuration (2026-11-12)

- Launcher: `python3 tools/browser/launch.py` from BugVault (opens a normal visible
  Chrome window, not headless). `--check` checks the binary and proxy listener only;
  `--prepare` prepares storage without opening Chrome.
- Profile: `.recon/browser/profile/` under BugVault, not the normal Chrome data
  directory. Private launch metadata/logs stay in `.recon/browser/` (gitignored).
- Web proxy: `http://127.0.0.1:8080`. This port was observed listening in Burp's
  process; TCP reachability alone is not proof of browser forwarding or HTTPS trust.
- MCP: `http://127.0.0.1:9876/mcp`. This is the control/data endpoint, **not** the web
  proxy. Do not configure FoxyProxy to use port 9876.
- The launcher fixes an HTTP proxy with no DIRECT fallback, includes loopback web
  traffic by removing Chrome's implicit loopback bypass, disables QUIC and restricts
  non-proxied WebRTC UDP. It refuses to start when the configured listener is absent.
  These are browser web-traffic controls, not an OS-wide egress firewall. It does not
  disable certificate checks, Chrome's sandbox or web security, or open a debug port.

No browser-control connection exists in this conversation yet. Preparing a folder or
starting Chrome is not proof that an agent can navigate or that traffic is captured.
Do not log in, read mail or perform target tests until the following checks pass.

## One-time operator connection and verification

1. Run the launcher to open the dedicated browser. Install/connect **Claude in Chrome**
   in that profile, and grant the required site permissions. Use fresh tab context to
   verify the browser tools are connected to this dedicated profile, not a personal
   window. If no browser tools are available, ask the operator to connect them; do not
   fall back to unsupervised shell/CDP automation or another browser/profile.
2. FoxyProxy may be installed in this profile, but launch-time proxy flags already
   select Burp. Avoid conflicting or DIRECT/bypass profiles. If extension-managed
   switching is desired, review a separate configuration and reverify routing before
   use; do not silently remove the fixed proxy.
3. Confirm Burp's listener is on loopback port 8080 and decide whether to forward or
   disable interception while navigating. Do not toggle the operator's intercept or
   global task settings without approval. A paused request is not a broken browser.
4. Trust Burp's CA using the appropriate certificate manager only after the operator
   approves it; prefer the narrowest supported trust scope. Never use a TLS-ignore
   flag or silently change system/keychain trust. Do not assume Chrome CA changes are
   profile-only. Confirm HTTPS works without a certificate warning.
5. On an owned lab/in-scope test page, navigate with a unique harmless marker. Confirm
   the exact request appears in Burp history (HTTP and HTTPS), and that browser HTTP
   traffic fails when the proxy is unavailable. Verify WebSocket capture if required.
   Do not claim routing is verified from flags, a socket check or an unrelated request.
6. Use an operator-provided **test mailbox** and dedicated A/V test accounts. No
   personal inbox, real-user session or password-manager import. Account creation,
   email sending, paid services, destructive actions and scope expansion need their
   own authorization. Signup setup does not grant permission to test a website.

## Operating rules

- Interactive browser flows use this connected browser through Burp. Other live
  tests default to the same path, but a standing campaign execution plan may permit
  scoped native requests or operator-run scanners when the program rules allow them.
  Record and bound those permissions as described in `../SKILL.md`; actions within
  an approved plan need no new exception each time. Direct Burp replay still follows
  `burp-workflow.md` and tool approval prompts. Missing browser access is not a grant
  to substitute another client, and a failed scope/rate/budget check cannot be bypassed.
  Generic brief/skill examples grant nothing. Normal software unit tests remain
  offline/owned-loopback and never automate the person's browser.
  Do not reroute the recon client through Burp: it deliberately refuses proxies,
  and a browser workflow is not native request evidence.
- Check campaign scope/methods before each flow. Login redirects and mailbox/provider
  domains may require a separate explicit grant; a redirect or discovered hostname
  never expands bounty scope. Mail providers are not themselves test targets.
- Use DOM-aware browser tools, not desktop clicks. For email links inspect the full
  destination first and confirm unfamiliar/suspicious domains with the operator.
  Stop for CAPTCHA, lockout, missing permissions, unexpected side effects or secrets
  that require the operator's input. Do not try to evade those controls.
- Burp MCP history reads can inspect relevant captured traffic. Modifying/replaying
  requests or configuring Intruder/Repeater is an approved external action, not
  unrestricted authority from having a proxy. Apply the caps and accounting in
  `burp-workflow.md`; do not intercept or modify unrelated traffic.
- Save relevant raw exports, screenshots and replay/control artifacts privately in
  the campaign's `.recon/`, with hashes and source labels. Never present Burp IDs as
  native `fact check` response IDs, or browser progress as server-side impact.
- Session state persists on disk for later use. Never commit, broadly copy or upload
  this profile. Finish sessions in accordance with the operator's retention policy;
  do not delete evidence or log out unrelated accounts.
