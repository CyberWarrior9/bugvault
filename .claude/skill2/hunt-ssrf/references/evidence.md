# Offline ledger and normalized evidence

`recon ssrf` never sends traffic, generates a payload, opens the browser or calls a
cloud service. Plan/status display operator-recorded cases; record appends immutable
event rows and copies evidence by SHA-256. Correlate only reads hash-bound files and
returns observations. It does not create native facts or promote findings.

## Exact context

Save `context.json` (CLI input paths are relative to your working directory):

```json
{
  "request_url": "https://app.example.test/api/import",
  "method": "POST",
  "account": "A",
  "role": "member",
  "tenant": "test-a",
  "workflow": "draft-preview",
  "field": "json.sourceUrl"
}
```

All seven fields are required when recording. Label non-applicable identity fields
`none`/`anonymous`. Exact URL variants remain separate within a normalized endpoint
family. Never put passwords/tokens in labels; URLs and captures are private too.
Plan/status without context show a blank-context checklist, not aggregated coverage.

```bash
python3 -m recon ssrf plan <campaign> --asset-id 12 --context context.json
python3 -m recon ssrf record <campaign> --asset-id 12 --context context.json \
  --case attribution --state blocked --note "Browser-control tools not connected"
python3 -m recon ssrf record <campaign> --asset-id 12 --context context.json \
  --case response-read --state observed --note "Controlled response canary; validator review pending" \
  --artifact .recon/captures/replay.txt --artifact .recon/captures/control.txt --requests-declared 2
python3 -m recon ssrf status <campaign> --asset-id 12 --context context.json
```

Artifact paths resolve relative to the campaign root, not the shell. Each must be a
regular file inside that root (including after symlink resolution), <=5 MB; at most
eight/event. `observed`/`negative` need two distinct file hashes and >=1 declared request.
Those are file/count checks, not judgments that the captures are valid replay/control.
Copied files live in `.recon/ssrf-evidence/<sha256>` with private permissions. Latest
hash failures are shown as unresolved, not silently trusted. History remains in
`ssrf_case_events`; scope/config or asset snapshot changes invalidate current outcomes
but retain old rows. No coverage/finding stage is automatically changed.

Optional campaign configuration:

```json
"ssrf": {
  "per_case_effort_cap": 3,
  "depth_grants": ["internal", "cloud", "credential"],
  "callback_hosts": ["*.callbacks.example.test", "receiver.example.test"]
}
```

`depth_grants` lists the deep branches the program's written rules allow —
`dns`, `internal`, `cloud`, `credential`, `protocol`, `execution`, or `["all"]`.
Granted branches run at full depth (credential read/use, host/port/protocol
swapping against internal services, execution proofs where the rules cover them);
every destination still passes scope checks and live tests still use the dedicated
browser through Burp. The cap is 1..10 recorded request-bearing events per case, an
advisory effort limit, not enforced network accounting. Declared requests sum only within the queried context
and are not debited from native budgets. Set up/verify separate operator accounting
before browser/Burp work. Callback grants are exact hosts or `*.` subdomain suffixes
(not a global wildcard); they permit **offline matching**, not sending, deeper scope
or automatic infrastructure ownership verification.

## Normalized correlation bundle, schema 1

Export the initiating request, application response, distinct negative control and raw
receiver events into private campaign files. Normalize them manually; no raw Burp,
Collaborator or HAR export schema is automatically parsed. A reference is exactly
`{"path":".recon/captures/file.txt","sha256":"<64 lowercase hex digits>"}`.

```json
{
  "schema_version": 1,
  "asset_id": 12,
  "request_url": "https://app.example.test/api/import",
  "context": {
    "request_url": "https://app.example.test/api/import",
    "method": "POST", "account": "A", "role": "member", "tenant": "test-a",
    "workflow": "draft-preview", "field": "json.sourceUrl"
  },
  "attempt_id": "bv_attempt_0123456789abcdef",
  "started_at": "2026-11-12T12:00:00Z",
  "ended_at": "2026-11-12T12:01:00Z",
  "callback_url": "https://bv_attempt_0123456789abcdef.callbacks.example.test/probe",
  "request": {"path":".recon/captures/request.txt","sha256":"REPLACE_WITH_SHA256"},
  "response": {"path":".recon/captures/response.txt","sha256":"REPLACE_WITH_SHA256"},
  "control": {"path":".recon/captures/control.txt","sha256":"REPLACE_WITH_SHA256"},
  "response_canary": "bv_read_9876543210abcdef",
  "events": [{
    "id": "receiver-001",
    "attempt_id": "bv_attempt_0123456789abcdef",
    "timestamp": "2026-11-12T12:00:02Z",
    "hostname": "bv_attempt_0123456789abcdef.callbacks.example.test",
    "protocol": "https",
    "origin": "unknown",
    "artifact": {"path":".recon/captures/event-001.txt","sha256":"REPLACE_WITH_SHA256"}
  }]
}
```

This is a template, not ready-to-run evidence. Replace hashes with hashes of actual
files; use fresh unpredictable attempt/response tokens, not the examples. Match only
HTTP(S) callback hosts explicitly granted in `ssrf.callback_hosts`. Attempt tokens
are 16..96 ASCII letters/digits/underscore/hyphen and bound in hostname/path, not just
the query. Input JSON <=1 MB, <=2,000 events, <=25 MB unique referenced artifact data;
timestamps need a timezone and an ordered <=600-second window. Start a separate
attempt/window for longer supervised async observations rather than widening forever.

```bash
python3 -m recon ssrf correlate <campaign> --asset-id 12 --bundle bundle.json
```

Matching requires the request to contain callback host/token, exact normalized event
host/attempt, in-window timestamp, DNS/HTTP(S) protocol and host/token in the raw event.
Repeated identical event IDs count once; conflicting duplicates fail validation.
`browser`, `analyst`, `scanner` and other origins are ignored. `unknown` stays
unattributed. `application` means **the operator supplied that attribution**; code
cannot certify source IPs, logs, timestamps or ownership. Freshness across campaigns
is not verified. Hashes detect changed bytes, not fabricated captures.

Results distinguish no interaction, unattributed interaction, DNS interaction and HTTP
interaction. `response_canary_observed` additionally requires an application-labelled
HTTP event, a 16..1024-byte response canary found in the response but absent from the
request/control. Empty canary means no readback claim. This is raw byte presence,
not a causal return-path or semantic response-body proof (headers/encoding/content
still need review). A caller-supplied reflected marker is rejected as readback.

Save results privately and bind them as ledger artifacts if useful. A successful CLI
exit means structurally valid processing, **not** SSRF proven or reportable. Burp IDs
are not `fact check` response IDs. Independent review still needs causal replay,
distinct negative control, forbidden boundary and demonstrated impact.
