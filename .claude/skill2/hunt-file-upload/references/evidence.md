# File-upload evidence rules

`recon upload record` is an offline operator assertion with structural checks. It
validates artifact roles, markers, controls and hashes; it cannot observe the
server. Validators replay with a fresh marker and a distinct negative control
before anything becomes a finding.

## Artifact roles

| Role | Holds |
|---|---|
| `original` | The bytes you uploaded; must carry the attempt marker. |
| `control` | The paired benign control; must lack the attempt marker and carry its control marker. |
| `request` / `response` | Redacted upload request and the server's response. |
| `retrieval` | Your own retrieval of the object (body plus relevant headers). |
| `derivative` | A thumbnail, preview or converted copy. |
| `worker-log`, `edge-log`, `origin-log`, `storage-log` | Owner-supplied or owned-lab logs for that layer. |
| `consumer-log` | The log of the component that actually consumed the file. |
| `effect`, `replay` | The demonstrated consequence and its independent replay. |
| `review` | Redacted configuration/source review notes. |
| `receipt` | Deletion, abort or expiry receipt (cleanup command). |

Paths are campaign-relative; obvious secrets are refused. Redact cookies, tokens
and personal data before writing the file.

## Facts

| Fact | `yes` needs | `no` needs |
|---|---|---|
| `accepted` | `response` | `response` |
| `stored` | marker in `retrieval` or `storage-log` | that artifact without the marker |
| `reachable`, `served` | marker in your `retrieval` | `retrieval` without the marker |
| `processed` | marker in `worker-log`, or a `derivative` distinct from `original` carrying it | `worker-log` without the marker |
| `effect` | state `impact-demonstrated`; distinct `effect`, `replay`, `control`; marker in effect and replay; control marker | not recordable |
| `executed` | everything for `effect`, plus marker in `consumer-log` and `--route execution` | not recordable |

Undeclared facts are `unknown`. `plan` and `status` list each current attempt's
facts separately: different uploads are different objects, so one object's
processing says nothing about another's publication.

## States and channels

States: `attempted`, `accepted-inert` (accepted, no effect claim), `rejected`
(accepted=no, or accepted and then refused by a correlated worker/storage layer),
`pending` (accepted, final state not reached), `blocked`,
`inconclusive`, `impact-demonstrated`, `review-candidate`, `review-clear`, `n-a`
(only for a non-applicable transport). Blocked, inconclusive, rejected, n-a and
review states need a `--note`.

Channels: `browser`, `burp`, `native` and `scanner` are live and charged to
`upload.budget`; `native` must cite every stored request (`--tool-ref native:ID`,
one per declared request, including the exact upload operation). `lab` is only for
loopback or reserved test hosts. `review` sends nothing: requests, bytes and
objects must be 0.

## Layer attribution

The default is `layer-unconfirmed`. Naming a layer (`--layer edge|origin|worker|storage`)
requires `--request-ref` and a matching `<layer>-log` artifact containing that
reference. Client-visible status codes, challenge pages and resets alone never
name a layer.

## Callback ladder

`python3 -m recon upload callback <campaign> --event N --kind dns|http|worker-trace
--url RECEIVER --sent-at T --observed-at T --deadline T --control-marker C
--artifact receiver-health=... --artifact receiver-log=...`

- Needs `callback` in `upload.case_grants` and a receiver approved in
  `upload.callback_hosts` (falls back to `ssrf.callback_hosts`). The receiver
  must bind the attempt marker and differ from the upload target.
- Timestamps are ISO-8601 with a timezone. A callback before the attempt is
  refused; after the deadline it is `inconclusive-late`.
- The receiver log must contain the marker and must not contain the control
  token.
- Classifications: `resolution-observed` (DNS), `fetch-observed` (HTTP),
  `processor-attributed` (worker log binds marker and `--job-id`). None of them is
  execution. `--health failed` records `receiver-unhealthy` and stops the host.

## Budget, stops and cleanup

- `upload.budget` (`requests`, `per_host`, `bytes`, `objects`) is one shared cap.
  An over-budget record is refused; record `--state blocked --stop-trigger budget
  --requests 0` and stop.
- A 429 must be recorded with `--stop-trigger rate-limit`, a 5xx with
  `server-error`. Any stop trigger blocks further traffic on the host until
  `upload resume`.
- `cleanup --outcome deleted|aborted|expired` needs a receipt naming the marker
  or `--object-ref`; `retained-by-owner` needs the owner's instruction;
  `failed|unverified` stops the host and must be resolved before resuming.

## Routes

`--route` names the class owner of a demonstrated consequence: `xss` needs
`served=yes`; `ssrf` a `fetch-observed` callback in the context; `xxe`
`xml-document` processing plus receiver evidence; `file-read` the inclusion or
archive case; `ssti` `processed=yes`; `idor-bola`/`access-control` the
cross-account cases; `execution` `executed=yes`; `file-upload` for policy, quota
or storage effects. Use one `--root-key` per root cause so derived consequences
are linked, not filed twice.
