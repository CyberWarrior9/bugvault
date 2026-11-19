# Claim dossier, JSON events and cleanup

`recon takeover` is an offline evidence ledger. A record is an operator assertion
with structural/integrity checks, not an executed test or a certified finding.
Candidate state never means finding `confirmed`; the existing validator still
needs replay, a distinct negative control, impact and reportability review.

## Wire schemas: inspect the installed implementation

Commands use these exact entry points:

```bash
python3 -m recon takeover import <campaign> <normalized-dns.json>
python3 -m recon takeover sync <campaign>
python3 -m recon takeover plan <campaign>
python3 -m recon takeover show <campaign> --candidate N
python3 -m recon takeover record <campaign> --file event.json
python3 -m recon takeover cleanup <campaign> --file cleanup.json
python3 -m recon takeover status <campaign>
python3 -m recon takeover verify <campaign>
```

The authoritative normalized **schema-1** DNS import and JSON event/cleanup
schemas are in `recon/takeover.py` (DNS validation may be delegated to
`recon/takeover_dns.py`). Consult those parsers for literal keys, state/case enums,
limits, artifact roles and required/optional fields before preparing JSON. Do not
submit arbitrary raw DNS output. If that implementation/schema is absent or
unfinished, preserve a review dossier and mark serialization blocked; do not claim
an import succeeded. Examples below are not substitutes for the installed validator.

### Current schema-1 event

Only these event keys are accepted: `schema`, `candidate`, `stage`, `state`, `note`,
`channel`, `requests`, `marker`, `control_marker`, `artifacts`, `account`, `resource`,
`cleanup_owner`, `cleanup_due`.

| Field | Rule |
|---|---|
| `schema`, `candidate` | Schema integer 1 and an actual integer candidate ID returned by this campaign. |
| `stage` | `precheck`, `claimable`, `claim`, `tls`, `chain`. |
| `state` | `observed`, `negative`, `blocked`, `inconclusive`; none is a finding state. |
| `note` | Required nonempty explanation, at most 2000 characters. Include limits and actual operator-plan refs, not secrets. |
| `channel` | `owned-lab`, `browser`, `burp`, `native`, `scanner`; default is `owned-lab`, so set it explicitly and never relabel live evidence to evade gates. |
| `requests` | Integer 0–10000, actual declared external count; positive live evidence needs a positive count and remaining shared declared budget. |
| `artifacts` | At most ten role-to-campaign-relative-path entries. Current evidence copies use SHA-256 under the campaign's `.recon/takeover/`. Each artifact is at most 5,000,000 bytes. |
| `marker`, `control_marker` | For observed claim/chain: distinct 16–96 character ASCII alphanumeric/underscore/hyphen markers; positive bytes contain the attempt marker, control contains its own marker and lacks the attempt marker. |
| Claim ownership/cleanup | Observed claim needs nonempty `account`, `resource`, `cleanup_owner`, and future timezone-qualified `cleanup_due`. |

A blocked example, **only after replacing candidate 1 with an actual campaign ID**:

```json
{
  "schema": 1,
  "candidate": 1,
  "stage": "claim",
  "state": "blocked",
  "note": "No approved provider claim execution path; preserve offline dossier.",
  "channel": "browser",
  "requests": 0,
  "artifacts": {}
}
```

`owned-lab` is reserved for genuinely owned simulated/loopback exercises, not
source review of a live candidate. Use an honest blocked/inconclusive event when
grants/path are missing. There is no `review` channel in this wire schema.

### Required roles for observed stages

| Stage | Required artifact roles | Ordered prerequisites |
|---|---|---|
| `precheck` | `review` | Candidate must be active and existing evidence integrity intact. |
| `claimable` | `provider`, `namespace`, `control` | Current observed precheck; live provider status must be freshly reviewed `vulnerable` (unknown/patched/edge-case remain blocked); typed DNS is at most 24 hours old, wildcard controls are negative and NS has parent/child referral context. |
| `claim` | `permission`, `ownership`, `before`, `after`, `control`, `cleanup_plan` | Current observed precheck and claimability; owned resource/deadline; no unresolved same-candidate cleanup; marker absent from before. |
| `tls` | `tls`, `control` | Current observed precheck and claim. |
| `chain` | `replay`, `control`, `impact` | Current observed precheck and claim; separate chain recording grant for live evidence. |

The parser binds candidate/DNS/trust/provider and policy snapshots and checks
required roles, local artifact integrity and certain marker differences. It does
**not** establish that the contents prove authorization, real hostname routing,
TLS, causality, cleanup or downstream impact. The claim stage's minimum required
roles do not include fresh replay; supply it as an additional artifact and require
it in validator review. Likewise inspect positive/negative byte meaning, not merely
unequal hashes. Structural acceptance must not lower the workflow proof bar.

Observed claims require `before`, `after` and `control` to be JSON capture receipts
with integer `status` (100–599), string `body` (the captured response bytes as UTF-8
text) and `request_url`/`url`, or an owned-simulation-only `host`. Before/after must
name the candidate; after must be 2xx. Live receipts require a full plain HTTP(S)
request URL passing current scope, port and path exclusions. Attempt markers are
checked in response `body`, not request metadata. Positive bodies cannot contain
the control marker. The attempt marker must not have appeared in an earlier
observed claim. Raw capture links/metadata may be attached additionally. A marker
only at a provider URL is rejected. Receipt labels remain operator assertions,
not independent checks that requests occurred; retain raw captures and chronology.
Validation and hash-bound copies use the same once-read artifact bytes.

### Current schema-1 cleanup

Exactly `schema`, `event`, `outcome`, `artifact`, `note` are accepted. `event` must
refer to this campaign's observed claim event, and outcome is `released`, `deleted`,
`retained-approved` or `failed`. The artifact is a campaign-local receipt path.

```json
{
  "schema": 1,
  "event": 14,
  "outcome": "released",
  "artifact": "evidence/resource-release-and-postcheck.json",
  "note": "Owned resource release receipt and post-cleanup check; review attached bytes."
}
```

Replace the event ID/path with real evidence. The parser stores the supplied
receipt, not an independently certified release. `status` lists no-receipt/failed
cleanup as open; even if a declared release closes that list, validators must
inspect resource binding, post-cleanup evidence and owner coordination below.
The receipt must be a JSON object with a `resource` field exactly equal to the
claimed resource label, plus actual release/deletion or approved retention and
post-check evidence. A label appearing only as a substring does not bind a resource.
Failed or overdue cleanup blocks further observed live evidence campaign-wide;
blocked/inconclusive events and later cleanup receipts can still be preserved.
Cleanup recording itself remains possible after scope is narrowed and executes
nothing. Bug-class exclusions and elapsed provider/DNS freshness are rechecked;
they cannot be bypassed by an older precheck event.

## Configuration gates, not execution approval

The takeover section of `scope.json` declares:

```json
{
  "takeover": {
    "rules_reviewed": "2026-11-16",
    "grants": ["claim", "chain"],
    "budget": 12
  }
}
```

This is a configuration shape, **not** a grant recommendation. Copy only the
families allowed by the actual written rules; use their actual review date and
bounded integer budget. An omitted family is not approved. These gates authorize
evidence recording only. They neither grant permission to act externally nor
reserve/enforce a network budget across browser, Burp, native or scanners. Keep the
program URL, permission source, scope, mode, HTTP method grants and separately
approved execution plan alongside the record. Do not interpret `budget` as free
provider allocations or an invitation to spend money.

## Dossier content by stage

These are semantic requirements for review, not invented wire field names.

| Stage | Bind and preserve |
|---|---|
| Candidate | Exact hostname/delegated zone, record type/value, candidate ID/context snapshot, in-scope rule and exclusions. |
| Inventory | Normalized DNS observation IDs/source hashes, resolver/time, missing types, parent/child distinction and wildcard controls. |
| Provider | Product/region/namespace, match basis, dated source/status, ownership requirements and explicit unknowns. |
| Precheck **before claim** | Exact CSP/cookie/CORS/OAuth/HSTS/mail/lifecycle references, production versus historical context, conditional route, missing links and review time. No references found is a valid limited precheck, not a reason to fabricate an edge. |
| Namespace | Authorized availability observation for the exact resource, time/source, reuse/verification constraints; not just a free-looking name or provider error page. |
| Permission/path | Program rule source, operator approval/run-plan ref, actual channel, scope/method/budget review, owned account/resource labels, timing, source-qualified request receipts and manually reconciled counts. |
| Claim evidence | Exact owned resource/account and hostname association, before-image, inert attempt marker served from the candidate hostname, fresh replay and separate negative-control marker/result. |
| TLS where needed | Exact requested hostname/SNI, certificate chain/validity/trust evidence and approved browser result; identify origin versus interception evidence. No "TLS valid" from an HTTP header or 200. |
| Chain | Its own grant, target-class proof, owned identities/state/readback, replay/control, lineage and limits. Marker hosting alone is not a chain. |
| Cleanup | Owner/deadline, exact resource/marker binding, release/deletion receipt or explicit retention instruction, post-cleanup observation, unresolved danger and coordination. |

## Artifact and chronology rules

- Keep redacted, campaign-local raw captures and provenance/hashes. A filename or a
  summary in chat is not verified artifact content. Do not claim hash binding,
  copying, enum support or a successful `verify` without executing that operation.
- Label source IDs honestly: Burp history IDs, native stored request IDs, imported
  files and lab logs are different namespaces. Never manufacture a native response
  ID for an external artifact. Retain capture times and relevant context.
- Bind permission and precheck before the external action; later review cannot
  retroactively authorize a claim. Preserve stale or invalid attempts as such.
- The baseline should show no attempt marker before claim; the claimed-host
  retrieval and independent replay should show it. A response from a provider URL,
  deployment screenshot or default edge page is not scoped-host control proof.
- A distinct negative control must test the asserted causal link with a separate
  owned marker/context. A second copy of the positive result, a preclaim image alone,
  or a wildcard-equivalent host is not automatically that control. State unresolved
  attribution/cache ambiguity rather than using a missing marker as proof of safety.
- Record actual external action/request counts under the campaign plan, including
  setup, redirects, retries, controls and cleanup. Recording is not enforcement;
  unavailable receipts or uncertain budget accounting block further live work.
- Redact cookie values, tokens, credentials and personal data. Use inert markers,
  not real user traffic. Structural secret checks, if present, are not general DLP.

## Cleanup is a separate fact

Use `cleanup --file cleanup.json` only with the implementation's actual schema.
Tie it to the correct candidate/event and owned resource. Preserve provider
deletion/release, post-cleanup hostname check and coordination/owner instruction.
"Delete planned," a closed tab, a deployment deletion without custom-domain
release, or a TTL interval is not verified cleanup. DNS caches and aliases can make
post-cleanup status temporarily inconclusive; record the time and limit honestly.

Do not modify the program's DNS, delete somebody else's resource or release an
unfixed dangle silently. If the owner requests retention, keep that instruction,
responsible person, exact resource and deadline. Failed/unverified cleanup stays
open and stops new live work until resolved under a reviewed plan. There is no
takeover `resume` command implied by this skill, nor automatic provider cleanup.

## Honest outcomes

Retain blocked/inconclusive reasons: missing grant, path, rules, provider review,
namespace proof, precheck, marker/control, TLS, downstream proof or cleanup. A
negative applies only to its captured context/time, not every provider or hostname.
Lab evidence remains labelled lab. All five passes can produce useful dossiers
without a claim; none of the offline commands promotes a finding automatically.
