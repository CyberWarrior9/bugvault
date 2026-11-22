# Offline cache and HTTP framing review

Implemented scope: local file analysis, private evidence journals and isolated
regression labs only. These commands never fetch a URL, prime/purge a cache,
forward captured HTTP, schedule a target job or promote a finding. The existing
`cache record/show/status/verify` event ledger remains separate and compatible.

## Capture census

Files must already be inside the campaign. Explicit campaign URL scope is used
for attribution, not as a grant to send traffic. Passive mode works; no live
request allowance is needed for local analysis. Do not import third-party data
without the applicable data-handling permission.

```bash
python3 -m recon cache import <campaign> --file evidence/capture.har --format har --account owned-v --role member --tenant owned --workflow preview
python3 -m recon cache reviews <campaign> --kind capture --limit 50 --offset 0
python3 -m recon cache review <campaign> --id <returned-review-id>
python3 -m recon cache verify-reviews <campaign> --limit 100 --offset 0
```

Supported formats: `har`, `burp-xml`, `burp-json`, `raw-pair`. Normalized HAR entries
are **not wire transcripts**. Burp imports need both request and response; imported
bytes are source-qualified, not authenticated by the importer. This reader does
not reuse the ordinary value-free endpoint projection, so static-looking paths
are not dropped. No native request/response IDs are manufactured.

A `raw-pair` manifest references two other campaign-relative files:

```json
{
  "schema": 1,
  "url": "https://app.example.test/account",
  "request": "evidence/request.http",
  "response": "evidence/response.http"
}
```

Raw HTTP/1 parsing retains original bytes and duplicate-header occurrences.
Missing/incomplete bodies are never negative evidence. Chunked or compressed raw
responses are not decoded and are not marked as complete entity bodies. HAR body
completeness checks its supplied decoded size; it does not establish origin
generation, transport authenticity or cache storage. `HIT`, `Age`, `Vary`, cookies
and cache-control directives seed observations only. Store/serve/layer remain
unknown until independent evidence establishes them.

## Behavior/layer profiles

Save this declaration locally, substituting the **returned capture review ID**:

```json
{
  "schema": 1,
  "capture": 1,
  "identity": {
    "behavior": "owned-preview",
    "policy_revision": "revision-1",
    "path_class": "preview",
    "representation": "html",
    "authority_context": "owned-v",
    "layer": "unknown",
    "pop": "unknown"
  },
  "observations": {
    "keying": "unknown",
    "forwarding": "unknown",
    "store": "unknown",
    "serve": "unknown",
    "ttl_seconds": null
  },
  "evidence": "evidence/owner-policy-note.txt"
}
```

```bash
python3 -m recon cache profile <campaign> --file evidence/profile.json
```

`keying` accepts `unknown`, `keyed`, `unkeyed`, `transformed`. Forward/store/serve
accept `unknown`, `yes`, `no`. TTL is `null` or an integer 0..31536000 seconds.
Every profile stays bound to one capture, context, method and response status.
Different behaviors or unknown layers are not merged. The observations are
operator assertions with source artifacts, not machine-verified cache facts.

## Per-attempt isolation receipts

Use the **returned profile ID**, not a stored native request ID:

```json
{
  "schema": 1,
  "profile": 2,
  "attempt": "owned-lab-case-1",
  "purpose": "isolated-observation",
  "state": "unknown",
  "viewer": "owned-a",
  "partition_sha256": null,
  "cleanup_owner": "operator",
  "artifacts": {}
}
```

```bash
python3 -m recon cache isolation <campaign> --file evidence/isolation.json
```

Purposes: `isolated-observation`, `owned-shared-confirmation`, `control/readback`.
States: `unknown`, `source-supported`, `contradicted`. `source-supported` requires
distinct `partition` and `control` artifact files; `cleanup` is an optional third
artifact. Labels and an optional declared lowercase partition SHA-256 never
certify separation. A random buster is not evidence of an isolated key. Missing
attempt/cleanup labels remain explicitly unknown. These receipts **never authorize
traffic**. Capture/profile dependency changes make descendants stale or invalid.

## Defensive HTTP/1 framing review

```bash
python3 -m recon http-review inspect <campaign> --file evidence/request.http --url https://app.example.test/account
python3 -m recon http-review show <campaign> --id <returned-review-id>
python3 -m recon http-review status <campaign> --limit 50 --offset 0
python3 -m recon http-review verify <campaign>
```

`--url` is attribution only and is never fetched. Request target and Host must
match it or the observation is rejected. `--kind response` inspects a captured
response. No raw bytes or credential values are printed.

Results are `well-formed-observation`, `reject`, or `inconclusive`. Checks cover
header syntax/bounds, duplicate length fields, simultaneous length/transfer
framing, body-length mismatch, unframed trailing bytes and a bounded basic chunked
subset. HTTP/2, chunk extensions/trailers and connection lifecycle attribution
are outside this validator. A rejection can mean malformed, incomplete or
unsupported capture syntax; it is **not smuggling confirmation or proof of an
actual parser disagreement**. No target parser-differential engine is installed.

`verify` exits 2 on integrity/staleness failure; a successfully recorded rejection
is not an import error. Verification reports its page bounds and `complete` flag.
Do not treat a successful bounded page as a full-journal audit.

## Evidence, reports and limits

- Original files are preserved; SHA-256-addressed private copies live under
  `.recon/offline-review/`, with newly created evidence files mode 0600. Do not
  publish this folder: the originals may include secrets. No general DLP is
  claimed. Changing an original is reported, even though its retained copy remains.
- Reports/CLI summaries contain hashes, labels, origins and diagnostics—not raw
  headers, URLs with queries or bodies. Avoid secrets in operator labels.
- Maximum 5 MB per source/artifact, 500 entries per import, 25 MB per capture
  envelope; raw HTTP messages 2 MB, header block 64 KiB, 200 header fields.
  Oversized envelopes fail, not silently disappear. Import writes no partial rows
  on a validation error; immutable unreferenced files can remain after I/O failure.
- Journal pages: 1..500 rows. `coverage.md` displays at most 50 records per journal
  and exposes truncation. Coarse coverage states never close these exact reviews.
- Cache event proofs additionally require complete stored viewer bodies; newly
  recorded external artifacts are copied privately and checked against originals.
- Loopback cache tests exercise poisoning/deception, private-response non-storage,
  a transformed-key collision and a distinct-key control. The HTTP loopback gate
  receives captures as JSON **data** and does not forward malformed messages.
  These tests certify neither real CDN behavior nor a real smuggling exploit.
