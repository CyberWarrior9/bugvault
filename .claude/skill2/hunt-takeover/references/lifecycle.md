# Hostname provenance and lifecycle graph

Use `takeover sync`, `plan` and `show --candidate N` as offline views of stored
inputs. They do not enumerate a zone, retrieve archives, fetch old JS, resolve
extracted names or enqueue target jobs. No new live discovery path is provided.

## Preserve what was seen, where and when

| Source | Keep | Limit |
|---|---|---|
| CT/imported certificate metadata | Original source/import identity, exact names, supplied not-before/not-after dates, capture time and hash | A certificate is not current service, ownership, DNS state or private-key control. An expired certificate is not a claimable resource. |
| Archive inventory/content | Snapshot time, original URL, source/import hash and whether content is actually stored | An archived link is historical use, not a current request or permission to fetch it. |
| Current HTML/JS/source map | Exact referring response/build, body hash, extracted reference and capture time | A string is not necessarily a reachable request or active trust configuration. |
| DNS capture/history | Exact owner/type/value/status, resolver/vantage/time and source hash | Different times/resolvers are observations, not an automatically reconciled current zone. |
| HTTP observations | Exact URL, status, capture time, response/source label, body/hash and truncation if known | 200 can be parking; failure can be transient. HTTP status cannot prove TLS or provider control. |
| Operator zone export | Supplied zone boundary, provider export identity/time and stated coverage | "Complete" applies only to the supplied export and its scope, not all external dependencies or current state. |

Track first/last **observed** times for a source/hostname and preserve individual
captures. Do not substitute import time for sighting time. Supplied certificate
validity times are not first/last use dates. Unknown timestamps stay unknown.
Deduplicate identical source content/imports by their actual identity/hash without
erasing provenance; a new DNS value, conflicting response or later source remains
a separate observation. Do not count duplicated imports as independent corroboration.
For existing asset rows, the current ledger retains inventory `first_seen`/
`last_seen` times and supplied certificate/archive attributes. Inventory times are
local ingestion/update observations, not a reconstruction of an external source's
original event time. Where that original time was never captured, report it unknown.

## Reverse production-reference edges

For each suspected stale host, show what still references it: parent production
page/response/build, exact target, relationship (link, script reference, policy,
cookie eligibility, OAuth reference or mail dependency), source/hash and dates.
Keep `current`, `archived`, `operator-asserted` and `lab` evidence visibly separate.
This answers "why investigate this forgotten name?" without pretending the
reference proves an available namespace or exploitable chain.

Normalize exact hostnames consistently with the implementation, preserving
meaningful scheme/port/path on URL edges and the raw source. Do not join an unrelated
substring, coalesce tenants from a guessed registrable domain, or equate wildcard
certificate/DNS names with every possible leaf hostname. Out-of-scope graph nodes
are intel-only; no claim, check request, provider query or traversal follows them.

## Resumption and integrity

Bind a candidate/event to the captured context, source hashes and relevant policy
snapshot. `verify` can detect missing/changed stored evidence; it does not certify
the supplied collector or refresh anything. On change, preserve the old event and
explain stale/conflicting evidence rather than rewriting its history. Do not reuse
an old namespace or trust check silently for a new provider/product/hostname.

Reports should state the collection window, known source gaps, unobserved record
types, referral/wildcard ambiguity, stale provider data, out-of-scope references,
blocked grants/path and unresolved cleanup. A closed bounded case is not exhaustive
takeover coverage, and a graph with no candidate is not a proof the zone is safe.
