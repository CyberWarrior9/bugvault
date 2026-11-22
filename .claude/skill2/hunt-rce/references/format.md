# Offline RCE declarations (schema 1)

All paths below are relative to an existing campaign folder. No command in this
guide sends a request; `--file` reads preexisting operator-supplied data. The
private journal keeps SHA-256-addressed copies under `.recon/offline-review/rce/`,
checks original-file changes, and prints hashes, origins and hashed label IDs rather
than URL query values or raw evidence. Do not include cookies, tokens, sensitive
records or untrusted instructions in labels. Evidence files may contain secrets; control
model/provider disclosure and retention accordingly.

## Sink declaration

```json
{
  "schema": 1,
  "family": "command-injection",
  "url": "https://app.example.test/owned-report",
  "method": "POST",
  "asset_id": 7,
  "field": "format",
  "location": "body",
  "context": {"account": "owned-a", "role": "member", "tenant": "owned", "workflow": "report"},
  "consumer": "report-worker",
  "sink_kind": "subprocess-argv",
  "runtime": "python",
  "tier": "review-only",
  "edges": [
    {"stage": "entry", "basis": "capture", "certainty": "direct",
     "reference": "capture-1", "artifact": "evidence/entry-redacted.txt"},
    {"stage": "sink", "basis": "authorized-source", "certainty": "direct",
     "reference": "owner-source-line-12", "artifact": "evidence/source-excerpt.txt"}
  ]
}
```

`family` is `command-injection` (`subprocess-argv`, `shell-construction`,
`process-wrapper`) or `deserialization` (`java`, `dotnet`, `php`, `python`, `node`,
`ruby`, `other`). The format is a **taxonomy**, not an executable technique.
`location` can be `path`, `query`, `body`, `header`, `cookie`, `file`, or `message`.
Graph stages can also include `decode`, `transform`, `store`, `queue` and `worker`;
each edge requires a reference and campaign-local artifact. `basis` is `capture`,
`authorized-source`, `owner-log`, or `owned-lab`; `certainty` is `direct`,
`inferred`, or `unknown`. Values in `context` are labels for operator-owned
accounts only. A label is not a scope grant.

A declaration is **source-supported** only with a matching existing in-scope
endpoint asset (not a service-wide row) whose route source is a HAR/Burp capture
or owner/lab source (not JS-only or mocked UI), a matching observed method and
exact path variant when present, direct edges through *every* recorded hop,
a named consumer, and an owner-log, authorized-source or owned-lab artifact for
the sink edge. Source and route labels are operator data: the ledger cannot
verify their meaning, runtime reachability or ownership. Captured serialized
syntax or a client-side reference without these conditions remains an unseeded
lead. Qualifying seeds `untested` coverage for its family, not `rce` or a finding.
Method grants are irrelevant to offline import; actual traffic follows the
separate program rules and connected executor workflow.

## Lab evidence receipt

```json
{
  "schema": 1,
  "sink": 1,
  "state": "observed",
  "channel": "owned-lab",
  "effect_channel": "processing",
  "artifacts": {"baseline": "evidence/lab-baseline.txt"},
  "note": "processor-observed"
}
```

States: `blocked`, `inconclusive`, `negative`, `observed`, `execution-claimed`.
Channels: `offline`, `owned-lab` only. `effect_channel` is `direct-output`,
`owner-worker-log`, `callback`, `timing`, `processing`, or `unknown`. A callback
or timing case can be recorded as `observed`; it cannot meet the execution
eligibility gate. There is **no native/Burp live-evidence import**, no execution
grant and no target command. The lab execution-claim variant additionally
requires `binding` with the same `account`, `role`, `tenant`, `workflow` and
`consumer` as the sink declaration, plus an `owned_object` label. It requires
distinct `markers` (`effect`, `replay`, `control`; each 16–96 safe characters),
`fidelity` for `baseline`, `effect`, `verification`, `negative-control` and
`positive-control`, each with `{"complete":true,"encoding":"identity"}`;
and strictly increasing timezone-aware
`times` (`baseline`, `trigger`, `replay`, `negative`, `cleanup`). Artifacts use
`baseline`, `trigger`, `replay-request`, `verification`, `negative-control`,
`positive-control`, `effect`, and `cleanup`; owner-worker-log cases additionally
need `worker-log` and `worker-replay`. A one-shot nonpersistent lab receipt can
record in `cleanup` that no owned object remained.

The assessor checks bounded file integrity, role presence, asserted binding,
marker separation, replay freshness, complete control captures and chronological
shape. These **do not certify that a server actually executed code**: all source, actor, worker,
fidelity and meaning assertions must be independently reviewed. Even
`eligible-for-validator` creates no BugVault finding and no target authorization.
`rce verify --limit 100 --offset 0` audits one page; `complete=false` means more
pages remain. Invalid or stale evidence exits nonzero. No P4 pilot is implemented.
