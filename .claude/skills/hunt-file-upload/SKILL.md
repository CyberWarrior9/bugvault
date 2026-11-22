---
name: hunt-file-upload
description: "Hunt file-upload weaknesses on authorized BugVault campaigns. Load for every file-upload coverage row and for avatar, attachment, import, media, archive, preview, signed direct-to-storage, resumable or URL-import flows. Inventory exact sinks with recon upload, test one inert dimension at a time with owned marker fixtures and distinct controls, and record intake, storage, processing, publication, retrieval and deletion as separate artifact-backed facts. A 201, thumbnail or callback is never execution; proven consequences hand off to the class owner."
license: "MIT; original BugVault workflow. No third-party technique text or payloads incorporated."
metadata:
  implementation: "recon/upload.py offline ledger; recon/score.py file-upload seeding"
  reviewed: "2026-11-14"
---

# Hunt: file upload lifecycle

An accepted file is data, not a program. Something has to consume it before it
matters: a server handler that interprets its type, a parser or worker, a browser
rendering it in an active same-origin context, or a separate include/read path.
So the unit of work is **one owned file's lifecycle through one exact sink**, and
each stage is its own fact: `accepted`, `stored`, `reachable`, `processed`,
`served`, `executed`, `effect`. A worker can process a file that is never
published; a static file can be served that nothing ever processed. Claim only the
stage your artifacts show.

## Before any live upload

The ledger's live gates are
`program_url` plus `upload.rules_reviewed` (the date you reviewed those rules),
`policy.mode` active or loud, the sink's method in `policy.allowed_methods`, the
case's family in `upload.case_grants`, and a positive `upload.budget`. That one
budget covers browser, Burp, native and scanner upload traffic. Recon cannot meter
Burp or a browser, so declare those counts honestly and reconcile them after each
run. The dedicated browser through Burp is the default live path. Without these
gates, work offline, in source review, or in an owned lab (`--channel review` or
`--channel lab`, the latter only for loopback or reserved test hosts).

## Workflow

1. `python3 -m recon upload sync <campaign>` builds sinks from captures and specs:
   exact URL × method × field × transport (multipart, batch, raw-body,
   signed-storage, resumable, url-import) × account/role/tenant/workflow. Flows the
   multipart seed misses, such as presigned storage, finalize calls or URL import,
   go in with `python3 -m recon upload declare <campaign> --url URL --transport T
   --field F --note 'where you saw it'`. A storage or CDN host seen in traffic is
   listed under `out_of_scope_destinations` and is never contacted unless the
   program scope names it.
2. `python3 -m recon upload plan <campaign> [--sink N]` shows 24 case cards per
   context with readiness and the reason. Work the baseline first:
   `intake-normal`, `retrieval-policy`, `cleanup`. Without a working baseline, a
   failed contrast means nothing.
3. `python3 -m recon upload fixture <campaign> --kind text|png|zip` writes a tiny
   inert marker file plus a distinct control. Upload only these, or equally inert
   owned files, and change **one dimension per attempt** against a valid control.
4. Record each outcome with its artifacts (see below). Retrieve only your own
   objects. Callbacks need an approved receiver; cross-account cases need two
   supplied test accounts captured on the same sink.
5. Delete or abort every object you created and record the receipt with
   `python3 -m recon upload cleanup <campaign> --event N --outcome deleted
   --artifact evidence/receipt.txt`. Attempts recorded with `--objects N` get a
   retention deadline; overdue cleanup shows in `upload status` and `coverage.md`.

Read [case details](references/cases.md) before choosing a case and
[evidence rules](references/evidence.md) before recording. Sources and their
limits are in [sources](references/sources.md).

## Recording evidence

```bash
python3 -m recon upload record <campaign> --context 7 --case intake-normal \
  --state accepted-inert --channel burp --marker bvup_<from-fixture> \
  --fact accepted=yes --fact stored=yes --fact served=yes \
  --artifact original=.recon/upload-fixtures/bvup_<marker>.txt \
  --artifact response=evidence/upload-201-redacted.txt \
  --artifact retrieval=evidence/own-retrieval-redacted.txt \
  --requests 2 --bytes 66 --objects 1 --object-ref <returned-id> \
  --tool-ref burp:history-118 --note 'Baseline lifecycle on owned test account A'
python3 -m recon upload status <campaign>
python3 -m recon upload verify <campaign>
```

Facts are checked against artifact roles, not taken on trust: `accepted` needs
the response; `stored` a retrieval or storage log carrying the marker; `served`
and `reachable` an owned retrieval; `processed` a worker log or a distinct
derivative carrying the marker. `effect` needs effect, replay and control
artifacts plus a control marker; `executed` additionally needs an attributable
consumer log and `--route execution`. Undeclared facts stay `unknown`, and
unknown is not no. Artifacts are copied by SHA-256 under `.recon/upload-evidence/`;
`verify` detects tampering and changed policy or context.

## Attribution, stops and routing

- A 403, 413, challenge, reset or missing marker does not name the layer that
  rejected the file. It stays `layer-unconfirmed` unless an owner-supplied or
  owned-lab log for that layer contains your request reference
  (`--layer edge --request-ref ID` plus an `edge-log` artifact).
- **Stop, do not retry around** a challenge or CAPTCHA, a 429, a 5xx, degradation,
  unexpected cost, real-user data, an unapproved host or redirect, an exhausted
  budget, a lost receiver or unresolved cleanup. Record `--state blocked
  --stop-trigger KIND`; the ledger then refuses further traffic on that host until
  `python3 -m recon upload resume <campaign> --host H --note 'why it is safe'`.
  A failed cleanup must be resolved with a receipt first.
- Hand off proven consequences and link one root cause with `--root-key`: inline
  same-origin rendering to `hunt-xss`, a fetch to your receiver to `hunt-ssrf`,
  template evaluation to `hunt-ssti`, cross-account access to `hunt-idor` or
  `hunt-access-control`. Proven code execution is the `execution` route, never
  relabelled access control. The validator decides what is reportable.


Disclosed-report precedent for this class — scale, highest-bounty disclosures and
corpus queries: [references/corpus.md](references/corpus.md). Precedent, not evidence:
a disclosed report shows a bug was accepted somewhere, never that this target has it.
