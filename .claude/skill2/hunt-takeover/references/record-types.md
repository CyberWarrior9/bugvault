# DNS breadth, referrals and wildcard controls

This is a capture-review workflow, not a DNS collector. Read `scope-policy` before
requesting any new collection. Nameservers, providers and mail dependencies outside
campaign scope do not become targets merely because a record refers to them.

## Observation census

For each exact owner name, preserve query type, response status, answer/authority/
additional sections when supplied, resolver or queried server, timestamp with
timezone, recursion/authority flags, query vantage and the raw capture's path/hash.
Retain the capture's actual meaning; do not label a recursive answer authoritative.
Carry TTLs and DNSSEC validation results if supplied, without inventing either.

| Record/surface | Preserve | Do not infer |
|---|---|---|
| A / AAAA | Separate address families, exact addresses, status and time | An absent A with a valid AAAA is not an absent host; a shared/cloud address is not available for reassignment. |
| CNAME | Exact owner and each captured target/hop | A known provider suffix or failure at one hop does not prove an available namespace. Uncaptured hops remain gaps. |
| NS | Exact delegated zone, parent referral and child/recursive answers separately | A differing set, missing address, lame server or one failed server is not ownership of the delegation or whole zone. |
| MX | Owner, exchange, preference, status and null-MX notation if present | No MX need not mean no mail: implicit-address fallback has different rules. Null MX is not a dangle. A missing exchange alone is not mail interception. |
| TXT / SPF | Raw bounded TXT evidence and exact referenced domains/qualifiers | `include`/`redirect` dependency failure can break SPF rather than authorize arbitrary mail. No automatic include expansion or delivery. |
| DKIM | Only captured selectors, CNAME/public-key references and source | A public key is not its private signing key; do not guess selectors or treat one CNAME as all-mail control. |
| SOA | Zone owner, primary server, serial and supplied timing fields | A serial difference or SOA primary is not a proof of delegated authority or control. |
| Wildcard | Exact supplied control labels, record types, answers/status and times | A wildcard alone creates no claimable resource and can contaminate both discovery and negative controls. |

Inventory scope is the supplied names, record types and capture window. Do not say
"every name" or "all DNS" from CT, a scanner's list or seven query types on one name.

## Status vocabulary

- **NXDOMAIN:** the queried name was reported nonexistent at that resolver/time;
  preserve alias-chain context and authority evidence. Not a resource-availability API.
- **NODATA:** an explicitly captured successful response with no RRset for that type,
  not a missing row or an empty tool field. Other types may still exist.
- **SERVFAIL, REFUSED, timeout, tool failure:** collection/resolution failure. These
  are not NXDOMAIN, NODATA, a confirmed dangle or a passing negative control.
- **Not collected:** unknown. No default "no", no fabricated resolver/time.

## Parent referral versus child answer

Bind the compared answers to the same delegated zone and compatible capture window.
Keep parent-side delegation/authority separately labelled from child-side NS data
and recursive cache answers. Parent referral data describes where authority is
delegated; a child answer describes what that server says. Divergence can be an
operational inconsistency, a transition, a cache/TTL issue or incomplete collection.
Multiple servers, partial failures, DNSSEC and provider namespace protection affect
exploitability. Even a fully captured mismatch needs a provider-specific, permitted
control path before any takeover claim. A successful claim would affect the delegated
subtree, not automatically the parent or every sibling; never rank NS as universally
"highest severity" from record type alone.

Missing parent referral? Record a gap, not a definitive NS diagnosis. The ledger
does not query a parent to fix it. Ask for an approved operator capture, or preserve
the blocked branch. Do not supply a live `dig`, scanner or resolver workaround.

## Wildcard comparisons

Use only operator-supplied, in-scope controls and their actual observed responses.
Prefer more than one unrelated control label at comparable depth/time and compare
A/AAAA/CNAME independently; wildcard synthesis and empty non-terminals vary by name.
Do not require new live random-label queries as an automatic prerequisite. Partial
controls, errors or unmatched timing mean ambiguity. A control receiving the same
provider error may be wildcarded, not independently negative. Keep control ownership,
source and marker distinct in later claim rehearsals.

## Normalized schema-1 import contract

`python3 -m recon takeover import <campaign> <file>` accepts the bounded normalized
schema-1 representation defined in `recon/takeover.py` and `recon/takeover_dns.py`.
Those validators are authoritative for literal keys, required fields, enums and
limits. The current wire form is:

```json
{
  "schema": 1,
  "source": "owned synthetic capture example; not live DNS",
  "observations": [
    {
      "name": "retired.example.test",
      "record_type": "CNAME",
      "value": "unused.provider.test",
      "result": "answer",
      "resolver": "192.0.2.53",
      "observed_at": "2026-11-16T10:00:00Z",
      "vantage": "recursive",
      "zone": "example.test"
    }
  ]
}
```

This partial synthetic capture intentionally supplies no address, provider-status,
namespace, referral or wildcard proof; importing it cannot establish claimability.

| Field | Current wire requirement |
|---|---|
| Envelope | Exactly `schema` (integer 1), `source` (nonempty, at most 1024 UTF-8 bytes), `observations` (0–2000 items). CLI JSON input at most 2,000,000 bytes. |
| Each observation | Required: `name`, `record_type`, `value`, `result`, `resolver`, `observed_at`, `vantage`. No other keys except the optional fields below. |
| `record_type` | `A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT`, `SOA`. |
| `result` | `answer`, `nxdomain`, `nodata`, `servfail`, `timeout`, `refused`. Non-answer values must be empty strings. An empty `answer` is a gap, not a negative. |
| `value` | One string, at most 4096 UTF-8 bytes: address, target name, `preference exchange` for MX (`0 .` for null MX), single-line TXT, or `mname rname serial refresh retry expire minimum` for SOA. Preserve multiple RR values as separate observations. |
| `vantage` | `recursive`, `parent-referral`, `child-authoritative`, `wildcard-control`. Parent-referral is NS-only and needs `zone`. |
| Optional | `zone`, `control_for`, `certificate_not_before`, `certificate_not_after`. `zone` must enclose the observed name on a label boundary. Certificate times are metadata, not ownership proof. |
| `resolver` / times | Resolver IP or hostname, not fabricated from the target; timestamps need ISO date/time with seconds and timezone. |
| Names | Lowercase IDNA normalization, at most one terminal dot removed, bounded labels/name; no literal wildcard owner. TXT/CNAME owners can include supported leading-underscore service labels. |
| Wildcard controls | `control_for` is required only for `wildcard-control` and must refer to an actual captured non-control name or explicitly captured zone. Use a distinct sibling/direct-child label at least 8 characters with at least 4 distinct alphanumerics and a letter. This lint does not establish randomness or a clean control. |

Current comparisons use a 24-hour window, with same-resolver requirements for
address and wildcard comparisons. A matching window is not proof of currentness.
The campaign also caps retained unique normalized DNS observations at 2,000;
additional imports exceeding that total fail before writes rather than silently
dropping history. Use explicitly bounded campaigns, not a completeness claim.
Raw flags, full DNS sections, TTL/DNSSEC details and collection errors outside the
accepted enums belong in preserved raw artifacts, not invented wire keys. Never
translate a tool failure into a supported negative merely to make JSON validate.

Raw command output, a provider screenshot, an arbitrary scanner report or a prose
"all records missing" claim is not this schema. Recheck the installed validator
before serializing; if unavailable, preserve an offline dossier rather than
claiming an import succeeded.

The normalized representation must keep the semantic distinctions above, including
per-observation errors, omitted/uncollected types, referral source and wildcard
controls. Preserve the original bytes privately alongside the import and hash.
Validation/import success does not make the collector authoritative or complete.
Repeated identical evidence may deduplicate, but changes and contradictory captures
must remain visible. Nothing in this import resolves a name or expands scope.
