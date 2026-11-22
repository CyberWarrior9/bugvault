---
name: hunt-cache
description: Web cache poisoning and deception evidence for authorized BugVault campaigns. Load for cache coverage rows and shared-cache store or serve questions. Review local HAR/Burp/raw captures, behavior profiles, isolation receipts and hash-bound marker evidence without sending traffic. Never infer cache causality from hashes or headers, prime or purge a shared cache, rotate viewers to force a hit, or promote a finding.
---

# Web cache poisoning and deception

Two mechanisms, one evidence bar. **Poisoning** is attacker-controlled content stored
under a key other viewers receive; **deception** is a private response stored under a
public-looking URL. Both are *cache and origin disagreeing about a request*, and both
are proven only by controlled store/serve contrasts — never by a `HIT` header, an
`Age` value, a vendor status or identical-looking HTML.

Read `scope-policy` first. This skill records evidence; it is not permission to touch
a shared cache, and the ledger has no executor.

## What exists

`recon cache record|show|status|verify` is an **offline hash-bound ledger**. Every
event binds one stored, in-scope native response (exact URL/path/query-hash/method/
status/body-hash plus a value-free cache-header fingerprint — raw header values are
never copied into event data) and optional campaign-local artifacts copied by
SHA-256. Cases are `CP-01..06` (poisoning hypotheses) and `CD-01..06` (deception
hypotheses); states are `blocked`, `inconclusive`, `negative`, `observed`,
`canary-proved`.

```bash
python3 -m recon responses <campaign> --limit 20        # stored response IDs
python3 -m recon cache show <campaign> --reference 12   # snapshot + events
python3 -m recon cache record <campaign> --file evidence/cache-event.json
python3 -m recon cache status <campaign>
python3 -m recon cache verify <campaign>                # exit 2 on any drift
```

The separate capture review journal preserves HAR-normalized versus raw-HTTP/1
fidelity, repeated response-header counts and body-completeness flags. It retains
private immutable copies; exports omit header/query values and bodies. This does
not change the ordinary HAR/Burp importer's projections or fabricate native IDs.

```bash
python3 -m recon cache import <campaign> --file evidence/capture.har --format har --account owned-v
python3 -m recon cache profile <campaign> --file evidence/profile.json
python3 -m recon cache isolation <campaign> --file evidence/isolation.json
python3 -m recon cache reviews <campaign> --limit 50 --offset 0
python3 -m recon cache review <campaign> --id 1
python3 -m recon cache verify-reviews <campaign>
```

Read `docs/offline-cache-http-review.md` for declaration formats and limits.
Profiles bind one capture/context and explicit behavior, policy, representation,
layer and POP labels; unknown is not a wildcard. Isolation is an operator receipt,
not a traffic grant: distinct partition/control files are necessary for the
`source-supported` label, but their hashes do not prove their meaning. A buster or
partition hash alone proves nothing. Inspect dependencies and cleanup ownership.
The paginated coverage report is an observation index, never class completion.

## Evidence rules

- **One event = one exact case**: family, state, channel (`offline`, `owned-lab`,
  `native`, `burp`), operation labels (principal/action/resource/method/variant) and
  a one-line value-free reason. No secrets in labels, reasons or URLs.
- **`canary-proved`** requires six *distinct-hash* artifacts — `baseline`, `test`,
  `replay`, `cross-viewer`, `negative-control`, `positive-control` — plus two
  distinct owned markers. The poison marker must appear in test/replay/cross-viewer
  and be absent from baseline and both controls; the control marker must appear in
  both controls; the cross-viewer artifact must *be* the referenced stored body.
  The viewer body must also be recorded complete.
  Deception proofs additionally require intended-private content assessment.
  A proof without an independent negative and positive control is rejected.
- **Writes** (`POST`/`PUT`/`PATCH`/`DELETE`) additionally need `before`/`after`/
  `cleanup` receipts with the marker absent before, present after, absent after
  cleanup.
- **Native channels** cite one stored completed `target-http` request ID per
  declared send; **Burp channels** cite distinct `burp:`-labelled external refs;
  offline and blocked events declare zero target requests.

## Live-labelled receipts are gated, not granted

A `native`/`burp` event needs `program_url`, `rules`, `cache.rules_reviewed`, a
`cache.grants` entry covering the event grant, non-passive mode, an allowed method
and at least one declared request; all such events share one declared
`cache.budget` the ledger refuses to exceed. These gates record operator
assertions — the ledger meters nothing, authorizes no traffic and does not
validate cache semantics. The dedicated browser through Burp remains the default
live path.



Layer attribution stays explicit: if the storing layer is unresolved, the honest
label is "controlled cross-context response observed; layer unknown". Consequence
claims (cache-mediated XSS, redirect, disclosure) hand off to `hunt-xss`,
`hunt-ato` or `hunt-idor` with the cache-delivery evidence and run under their own
gates. The owned-loopback lab (`tests/test_recon_cache_lab.py`) proves the ledger's
evidence logic only — not Cloudflare, CloudFront or Fastly behavior.

Disclosed-report precedent for this class — scale, highest-bounty disclosures and
corpus queries: [references/corpus.md](references/corpus.md). Precedent, not evidence:
a disclosed report shows a bug was accepted somewhere, never that this target has it.
