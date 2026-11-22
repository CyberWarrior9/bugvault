# File-upload lifecycle cases

`recon upload plan` shows these 24 cases for every sink context. **Where**:
`live` = a live channel is allowed once the gates pass; `tiny` = live only at or
below 4096 declared bytes; `review` = source/config review or owned lab only
(`--channel review` or `--channel lab`); `review unless callback` = live only when
`upload.case_grants` includes both `transport` and `callback` and a receiver host
is approved. Every live attempt changes one dimension, uses a fresh inert marker
and a distinct valid control, and stays inside the shared budget.

| # | Case | Grant | Where | Comparison | Decision limit |
|---|---|---|---|---|---|
| 1 | `intake-normal` | none | live | One allowed small owned marker file through the intended feature; observe request, returned ID, status, owned retrieval and delete. | Lifecycle baseline; a 201/200 alone is not a defect. |
| 2 | `intake-role` | cross-account | live | Uploader role versus a second owned test role on the same operation. | Attribute acceptance or denial to role and exact operation, not the host. |
| 3 | `contrast-extension` | contrast | live | Inert unneeded extension versus an allowed same-size control; no executable suffix. | A validation observation, not code execution. |
| 4 | `contrast-media-type` | contrast | live | Same benign bytes declared with two ordinary media types the policy permits. | Client-declared type is not a content check. |
| 5 | `contrast-format` | contrast | live | Small benign wrong-format bytes under a nominally accepted extension versus a valid control. | Separates signature/format from declared-type checks; no active or polyglot content. |
| 6 | `contrast-filename` | contrast | live | Benign case, spacing, Unicode or length variant versus a simple name. | Compare display name, stored key and download header; no traversal, overwrite or metacharacters live. |
| 7 | `batch-items` | contrast | live (multipart/batch) | Two tiny permitted files with different markers. | A batch verdict must not mask an unvalidated item; no exhaustion. |
| 8 | `size-boundary` | contrast | tiny | Tiny boundary around a documented tiny or lab cap; count envelope bytes separately. | Never cross a large live threshold. |
| 9 | `quota-count` | none | review | Declared quota versus a one-at-a-time owned count; configuration for larger bounds. | No storage filling; stop before cost impact. |
| 10 | `signed-storage` | transport | live (signed-storage) | Signing policy, object key, finalization and publish checks; only an in-scope owned bucket. | A storage PUT is not app approval or publication; storage host needs its own scope. |
| 11 | `resumable-assembly` | transport | live (resumable) | Two tiny owned parts; final length versus declared total and finalization. | Whole-object limits must hold, not only part limits. |
| 12 | `resumable-abort` | transport | live (resumable) | Owned session/partial visibility, abort, expiry, cleanup. | No cross-owner session IDs on real users. |
| 13 | `url-import` | transport (+callback) | review unless callback | A documented import-from-URL feature fetching from an approved owned receiver. | Fetched bytes, job and publication are separate; no internal addresses or redirect probing. |
| 14 | `derivative-metadata` | derivative | live | One valid tiny image with a harmless metadata marker versus its thumbnail/metadata display. | A derivative proves processing only. |
| 15 | `worker-observation` | derivative | live | Ordinary preview/transcode status plus owner worker logs. | Associate with job ID and version; no crafted converter directives. |
| 16 | `xml-document` | none | review | Parser configuration and external-resource policy; an ordinary document in a lab. | XML inside a format is a candidate; resolution needs real external evidence. |
| 17 | `quarantine-scan` | derivative | live | Pending → accepted/rejected → published under normal polling. | No visibility before approval; a scanner alert is not malware execution. |
| 18 | `archive-extraction` | derivative | live | Tiny flat archive of owned benign files; extraction destination and entries. | Normal extraction is not path escape; escape controls are review/lab. |
| 19 | `process-arguments` | none | review | Worker invocation; a local stub records inert argument boundaries. | A process name or argument sink is a candidate only. |
| 20 | `inclusion-path` | none | review | Preview/include/path mapping with a lab-only owned file reference. | Needs an influenced path and real read semantics; no system files. |
| 21 | `retrieval-policy` | none | live | Own object: origin, Content-Type, Content-Disposition, X-Content-Type-Options, embedding context. | Static bytes or an attachment do not show execution. |
| 22 | `published-authz` | cross-account | live | Second test account requests the first account's test-owned object, if policy allows. | Needs replay and a distinct control; never guess IDs. |
| 23 | `edge-callback` | none (callback evidence needs `callback`) | live | One inert request correlated with owner edge/origin/worker logs; optional receiver token and control. | Edge block stays unconfirmed without correlation; contact is not execution. |
| 24 | `cleanup` | none | live | Delete/abort original, derivatives and parts; receipts and retention gaps. | Unverified cleanup is a stop, not permission to leave artifacts. |

## Near misses

- A thumbnail, a metadata echo or a job ID is `processed=yes`, nothing more.
- A served file with `Content-Disposition: attachment` and `nosniff` is a
  retrieval policy observation, not an XSS lead; inline same-origin rendering
  evidence belongs to `hunt-xss`.
- A storage PUT returning 200 does not mean the application accepted or published
  the object; finalize/publish is a separate operation and often a separate host.
- A rejected contrast covers only that contrast. It never closes the other cases
  or the coarse `file-upload` row.
- Missing worker logs are `unknown`, not `processed=no`.
