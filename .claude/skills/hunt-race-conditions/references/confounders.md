# Confounders and stop boundaries

- Session lock, per-user limiter, connection coalescing, upstream queue or app
  transaction serialization may remove overlap without proving the invariant safe.
- Cache/replica/UI state and request TTFB may not reflect committed state. Use an
  independent authoritative readback and declared observation deadline.
- A timeout/error may have committed; do not retry a mutation until the owned
  oracle reconciles it. A 429, 5xx, challenge, lost observer, unexpected effect
  or unresolved cleanup stops new attempts.
- Separate dispatch, transport release, application check/use overlap and durable
  effect. Source review is a lead; lab results only prove the lab fixture.
- Existing `recon send` pacing/budgets and Burp MCP are **not** a group reservation
  broker. M5a is human-operated and declared accounting only. M5b/M6 require
  separate frame-level and cross-process enforcement acceptance before a live go.
