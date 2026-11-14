---
name: synthetic-ui-mapping
description: Run opt-in authorized BugVault Playwright SPA exploration with mocked frontend state, recording client-attempted calls without confusing mocked UI access with backend authorization.
---

# Synthetic UI mapping

Read scope-policy first. Require permitted active mode, `runtime.enabled=true`, compatible Playwright and Chromium. Start with `runtime.live_api=false`; keep configured routes/clicks bounded.

The browser receives synthetic local state and mock API replies. Every allowed real HTTP read goes through the scoped client; WebSockets are intercepted. Do not add network passthrough to fix a rendering problem.

Label discoveries `synthetic-ui` or `client-attempted`. A menu rendered with mocked admin permissions proves neither a working backend operation nor privilege escalation. If live GET is explicitly enabled, real requests still are not independent security validation. GET requests may have side effects; review exclusions.

Output attempted endpoint/method/parameter surfaces, blocked actions and browser coverage gaps. Implementation: `recon/runtime.py`.
