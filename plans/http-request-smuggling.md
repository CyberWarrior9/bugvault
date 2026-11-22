# Build plan — `hunt-http-smuggling`

HTTP request smuggling and desync for BugVault.
Drafted 2026-11-16. Target branch `recon-engine`. Baseline: 511 tests green.

**Implementation status, November 20:** the historical proposal below is not an
execution grant or an inventory of installed features. Installed: `hunt-http-smuggling`
and explicit review-row routing; `recon http-review inspect|show|status|verify` for
local, conservative HTTP/1 capture lint; a private hash-bound observation journal;
bounded coverage reporting; and a loopback JSON review-gate regression test. The
gate treats captures as data, never forwards malformed HTTP and proves no desync.
There is **no** smuggling CLI, target parser-differential engine, raw-socket/H2
transport, timing-probe sender or live pilot. In particular, the historical claim
below that timing tests are “self-only by construction” is not a safety guarantee.
See [current offline formats and limits](../docs/offline-cache-http-review.md).

---

## 1. Corpus position

| Metric | http-smuggling |
|---|---|
| Reports | 89 |
| **Bounty rate** | **44%** — one of the highest in the corpus (`README.md:106` names it alongside memory corruption 84% and privilege escalation 46%) |
| Corpus average | 43% |

Low volume, high conversion. That profile fits a class with a high technical barrier:
few people test it properly, and those who do get paid.

plan4 row 22 already specifies it: `HTTP smuggling (E2) | L2+WAF profile | CL.TE/TE.CL
timing, own-session poison | **raw socket executor**`.

---

## 2. Organizing thesis — a disagreement about where one request ends

> Smuggling is **two HTTP implementations disagreeing about the boundary between one
> request and the next.** Everything else is a consequence.

Kettle's 2025 paper puts it plainly: *"the fatal flaw in HTTP/1.1 is that the
boundaries between individual HTTP requests are very weak"* — and that a decade of
patching implementations has not fixed the protocol.

Worth noting across plans: this is the **third parsing-discrepancy class** in the set.
Cache poisoning is a disagreement about the *key*, cache deception about
*cacheability*, smuggling about the *boundary*. The WAFFLED paper
(arXiv 2503.10846) generalises the same pattern to WAFs, and it surfaced in both this
search and the cache one. §9 proposes the shared primitive that follows.

---

## 3. The canon — Kettle's four papers plus a 2026 follow-up

This is the best-sourced class in the whole effort: four primary papers from one
researcher, each superseding part of the last.

### 2019 — *HTTP Desync Attacks: Request Smuggling Reborn* (Black Hat USA, DEF CON 27)

The foundational paper. CL.TE, TE.CL, TE.TE, and the **timing-based detection
method** that makes probing tractable.

### 2021 — *HTTP/2: The Sequel is Always Worse*

H2.CL and H2.TE — smuggling through the **HTTP/2-to-HTTP/1.1 downgrade**, plus
request splitting via CRLF in HTTP/2 header values. This is where the class moved
when classic CL.TE was patched.

### 2022 — *Browser-Powered Desync Attacks* (Black Hat USA, DEF CON 30)

| Take |
|---|
| **Client-side desync** — the victim's own browser as the delivery platform, which *"reaches single-server sites and internal networks"* |
| **CL.0 / 0.CL** — the server ignores `Content-Length`, so no front-end/back-end pair is needed at all |
| **Pause-based desync** — split the request so that *"if the client follows up with the second half of the HTTP request, it will be interpreted as a fresh request"* |

The significance: it removes the precondition. Before 2022 you needed a proxy chain;
after it, a single server can be vulnerable.

### 2025 — *HTTP/1.1 Must Die: The Desync Endgame* (Black Hat USA, DEF CON 33)

The current state of the art, and the most consequential for target selection.

| Take |
|---|
| **Two new desync classes**, used to compromise **three major CDNs** |
| Reported bounties of **~$350K across Cloudflare, Netlify and LastPass** (figures vary by source; one pre-talk announcement said $200k+) |
| The vector is **front-ends that accept HTTP/2 and downgrade to HTTP/1.1 internally** — Cloudflare's downgrade is named specifically |
| Conclusion: retire HTTP/1.1 on **upstream** connections; the only durable fix is binary framing end to end |
| One headline puts the exposure at **34% of the web** |
| Whitepaper, toolkits and remediation guides at `http1mustdie.com` |

### 2026 (March) — *Conquering the 0.CL Challenge*

A follow-up on the 0.CL class specifically — the newest material in this plan and
newer than any other source in the whole set.

---

## 4. The 2026 reality check — what is actually exploitable

mind-hunt and Kettle 2025 agree, and this should drive target selection rather than
starting from CL.TE out of habit.

### mind-hunt — `hunt-http-smuggling/SKILL.md`, 81 lines

SHA-256 `9b2bac1800746f1e987fcebd3790709401a25c68e9249fa6eeaeafbe1219e674`

Short, but its two best sections are exactly the ones nothing else has:

| Take | Anchor |
|---|---|
| CL.TE worked example | L9-19 |
| Detection | L20-26 |
| Impact chain | L27-35 |
| **Target-Suitability Matrix (2026 reality check)** | L36-53 |
| **Operator fingerprint quick-check** | L54-63 |
| **H2.CL / H2.TE — "the modern dominant vector"** | L64-71 |
| Chains | L72-81 |

The suitability matrix is the thing to port first. Classic CL.TE/TE.CL is largely
patched across major stacks; spending the budget there is how this class gets written
off as dead. The live surface is the **downgrade hop**.

### The suitability matrix, ported

mind-hunt L36-53, with its own framing: *"The classic CL.TE / TE.CL payloads are NOT
universally exploitable in 2026. Modern proxies are RFC 9112 strict by default.
Fingerprint the front-end BEFORE investing time."*

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Note |
|---|---|---|---|---|---|
| Nginx ≥ 1.21 | no | no | partial | partial | RFC-strict; rejects CL+TE with 400 |
| Caddy 2.x | no | no | — | — | hardened by default |
| Envoy ≥ 1.20 | no | no | partial | partial | hardened in most paths |
| **HAProxy ≤ 2.4** | **yes** | **yes** | — | — | CVE-2021-40346 |
| AWS ALB + specific upstream | partial | partial | **yes** | **yes** | disclosed-paid 2022-2024 |
| **Cloudflare → S3 / Lambda chains** | — | — | **yes** | **yes** | H2-downgrade remains viable |
| Older F5 BIG-IP (TMM < 16) | **yes** | — | — | — | vendor advisories |
| Citrix ADC / NetScaler (older firmware) | **yes** | **yes** | — | — | disclosed 2020-2022 |
| Squid 3.x | **yes** | — | — | — | older deployments |
| Apache Traffic Server (older) | **yes** | **yes** | **yes** | **yes** | PortSwigger research |
| Custom Python / Go proxies | **yes** | **yes** | — | — | frequently miss RFC enforcement |

mind-hunt backs the Nginx row empirically — *"Verified locally on Nginx 1.27 — all 9
documented variants killed by front-end"* — and references its own
`docs/verification/phase2h-smuggling-cachepoison.md`. Treat the table as a prior to
re-verify per target, not as ground truth: firmware and config override the vendor
default, and the matrix is a 2026 snapshot.

### Operator fingerprint quick-check

One request, before anything else (mind-hunt L54-63):

```bash
curl -sI https://target/ | grep -i "Server:"
```

| Signal | Action |
|---|---|
| `nginx/1.21+`, `Caddy`, `envoy` | classic CL/TE is dead — pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or look for a legacy proxy further upstream |
| `HAProxy`, or a header pointing at AWS/CDN | run the full technique matrix |
| no `Server` header | assume hardened, but run one `space-before-colon` probe; if it does not 400, dig further |

This slots in as `hs-fingerprint` (§10) and populates `smuggle_topology.front_end`
and `front_end_version` (§13).

### Priority order this implies

```
1. H2 -> H1 downgrade present?        -> H2.CL / H2.TE      (dominant, 2021 + 2025)
2. Single server, no proxy chain?     -> CL.0 / 0.CL         (2022 + 2026)
3. Browser-reachable victim?          -> client-side desync  (2022)
4. Legacy proxy chain, HTTP/1.1 only? -> CL.TE / TE.CL / TE.TE  (cheap to check, rarely live)
```

---

## 5. HackTricks — the deepest coverage of any class in this effort

Six files, roughly **100 KB total** — more than its XXE (876 lines) or file-upload sets.

| File | Size |
|---|---|
| `http-request-smuggling/README.md` | **29,945 B / 516 lines** |
| `http-request-smuggling/browser-http-request-smuggling.md` | 22,658 B |
| `http-request-smuggling/request-smuggling-in-http-2-downgrades.md` | 10,323 B |
| `h2c-smuggling.md` | 11,344 B |
| `http-response-smuggling-desync.md` | 11,920 B |
| `http-connection-contamination.md` | 7,805 B |
| `http-connection-request-smuggling.md` | 4,422 B |

README structure, and it is unusually well-organised:

| Section | Anchor |
|---|---|
| Theory · **Reality** · Particularities | L20, **L35**, L40 |
| CL.TE · TE.CL · **TE.TE (obfuscated Transfer-Encoding)** | L56, L71, **L90** |
| **Finding CL.TE using timing techniques** | **L111-136** |
| **Finding TE.CL using timing techniques** | **L137-153** |
| Probing | L154-169 |
| **Forcing via hop-by-hop headers** | **L170-183** |
| Bypass front-end security controls | L186-221 |
| **Revealing front-end request rewriting** | L222-245 |
| **Capturing other users' requests** | L246-271 |
| Reflected XSS via smuggling | L272-297 |
| On-site redirect → open redirect | L298-331 |
| **→ web cache poisoning** | **L332-361** |
| **→ web cache deception** | **L362-382** |
| **Weaponising with response desynchronisation** | L383-390 |
| Turbo Intruder scripts, CL.TE and TE.CL | L393-481 |
| Tools | L488-495 |

L111-153 is the single most important block: the **timing techniques** are both the
primary detection method and the one that is safe by construction (§7).

---

## 6. Which surfaces — hop structure, not parameters

This class differs from every other plan: there are no vulnerable parameters. The
target is the **connection topology**.

### What to establish about the target

| Fact | Why it matters |
|---|---|
| Is there a front-end at all? | no chain → CL.0 / client-side desync instead of CL.TE |
| Does the front-end accept HTTP/2? | prerequisite for H2.CL / H2.TE |
| **Does it downgrade HTTP/2 to HTTP/1.1 upstream?** | the dominant modern vector (Kettle 2025) |
| Does the back-end connection get reused? | classic smuggling needs reuse; client-side desync does not |
| Which CDN or proxy, and which version? | mind-hunt's operator fingerprint quick-check |
| Do different paths route to different back-ends? | a path that reaches a different origin is a separate hop pair |
| Is HTTP/1.1 reachable directly? | `fingerprint.py:121`'s `origin-ip` pack bypasses the normalising front-end |

### Endpoint roles — three, and they are different endpoints

```
PROBE endpoint       accepts POST with a body; response time is measurable;
                     ideally boring and idempotent
DIFFERENTIAL target  a path whose response is distinctive enough that a smuggled
                     prefix visibly changes it  (e.g. a 404 vs 200 boundary)
VICTIM endpoint      what the smuggled prefix is aimed at — the thing whose response
                     you want the next requester to receive
```

Most published methodology collapses these. Keeping them separate is what makes a
desync reproducible: the probe proves the boundary disagreement, the differential
proves direction, and the victim proves impact.

### The request components in play

```
boundary headers   Content-Length, Transfer-Encoding
TE obfuscation     whitespace, casing, duplicate headers, line folding,
                   Transfer-Encoding: chunked\r\nTransfer-Encoding: x  (TE.TE, L90)
hop-by-hop         Connection-listed headers to strip the other hop's view  (L170)
HTTP/2             pseudo-header manipulation, CRLF in header values, explicit
                   content-length in h2  (H2.CL / H2.TE)
h2c                Upgrade / Connection to reach a cleartext h2 back-end
timing             the response-delay signal that detection depends on
```

---

## 7. The timing probe is the method, not a precaution

A desync corrupts **the next request on that connection**. That is mechanical, not a
policy position — and the canonical methodology answers it directly.

**Timing-based detection only affects your own connection.** HackTricks L111-153
gives both forms: a CL.TE probe where the back-end waits for a body that never
arrives, and the TE.CL inverse. The signal is *your own* request hanging. Nothing is
queued for anyone else.

Two reasons that ordering is correct, and the second is the one that governs:

1. The timing probe is non-interfering by construction.
2. **A corrupted connection is indistinguishable from a desync.** If you probe by
   firing malformed requests at a shared connection pool, every subsequent anomaly
   could be your own earlier garbage. You cannot tell a finding from your own noise,
   and the result is unreportable either way.

So the sequence is: **timing probe → confirm on a connection you hold → demonstrate
impact on a second client you also control.**

### The second client is not optional — and it is not a victim either

An earlier draft of this plan stopped at "your own second request", citing plan4
row 22's "own-session poison". mind-hunt corrects that, and the correction is right:

> the smuggled-request effect MUST land on a request issued by a **different
> client/session**, not your own follow-up. A timing delta in your own browser alone
> is parser disagreement, not exploitable smuggling.
> — `hunt-http-smuggling` L79

Its cache skill states the same bar independently: *"If only the attacker sees the
effect, it's not cache poisoning"* (`hunt-cache-poison` L224).

That is an impact argument and it stands: a desync you only observe in your own
request stream has not shown that anyone else's request can be affected.

But note what mind-hunt does **not** say. The second client is a *second client*, not
a third party. Its own 10-minute reproduction spells out the method —
*"fetch the URL from incognito/different IP"* (`hunt-cache-poison` L230). Two
clients you control on the same connection or pool clears the bar without queuing a
prefix for a real user.

So the demonstration is: **client A smuggles, client B — your second session, a
second IP, or an anonymous fetch you issue — receives the effect.** Both references
stored, both yours. That satisfies mind-hunt's gate, keeps the artifact replayable by
a triager, and is the shape the `own_connection` ledger column and the
`own-connection` eval (§16) already assume.

The ledger records it as `attempt_kind` plus two response refs; §14 binds
`hs-prefix` to a marker appearing in the **second client's** response rather than the
first's.

---

## 8. The blockers and how each falls

| Blocker | What it does | How it falls |
|---|---|---|
| **HTTP/2 end to end, no downgrade** | no HTTP/1.1 boundary to disagree about | Find a path that *does* downgrade — different hostname, different route, a legacy origin. Kettle 2025's entire point is that downgrade is near-universal at the edge |
| **Front-end normalises `Transfer-Encoding`** | your TE never reaches the back-end intact | TE.TE obfuscation (L90): whitespace, casing, duplicates, line folding. The normaliser and the back-end disagree about which TE wins |
| **WAF rejects malformed TE/CL** | request dropped at the edge | Hop-by-hop forcing (L170), obfuscation variants, or reach the origin directly via the `origin-ip` pack |
| **`Connection: close` / no back-end reuse** | classic smuggling has nothing to poison | **Client-side desync** (2022) needs no back-end reuse at all; CL.0 / 0.CL need no proxy chain |
| **Single server, no proxy** | the classic precondition is absent | Exactly what CL.0 and the 2022/2026 work address |
| **CDN normalises everything** | edge sanitises before the origin sees it | Target the downgrade hop *inside* the CDN (Kettle 2025 compromised three of them), or reach the origin directly |
| **Short connection lifetime** | the poison window closes | The window is the measurement — record it. Pause-based desync (2022) also decouples the two halves in time |
| **h2c not reachable** | no cleartext h2 back-end | `h2c-smuggling.md` covers the Upgrade paths; absence is a negative result, not a dead end |

Cross-cutting: **establish the hop topology before choosing a technique.** Every row
above is a statement about topology, and §6's fact list is one request pair plus a
fingerprint read.

---

## 9. The executor gap — and a shared primitive

plan4 row 22 says "raw socket executor". That is necessary but it is **not the
primary need**, and an earlier draft of this section had the priority backwards.
mind-hunt states the correction directly:

> Tools that send HTTP/2 raw frames (Burp's HTTP Request Smuggler, `h2csmuggler`,
> `smuggler.py`) are the right starting point against CDN-fronted targets. **Avoid
> HTTP/1.1-only test clients (curl, raw sockets) against H2-front-ended targets —
> you'll send the wrong protocol entirely.** Most CDN+origin chains in 2024-2026 use
> this exact topology.
> — `hunt-http-smuggling` L68

Built raw-sockets-first, `recon/transport.py` would be unable to reach the majority
of live targets — it would speak HTTP/1.1 at front-ends that negotiate h2, and every
negative result would be an artifact of the client, not the target. So:

```
PRIMARY — H2.CL / H2.TE need frame-level HTTP/2 control:
  - explicit content-length in an h2 request
  - CRLF in header values
  - pseudo-header manipulation
  - no automatic length recalculation on downgrade
  -> the h2 / hyper-h2 library, same as the race plan's single-packet work
  -> covers §4 priority 1, the dominant 2021 + 2025 surface

SECONDARY — HTTP/1.1 desync needs byte-exact control:
  - malformed or conflicting Content-Length
  - obfuscated Transfer-Encoding the library would normalise or reject
  - no automatic header fixing, no automatic chunked encoding
  -> Python socket/ssl with hand-built request bytes
  -> covers §4 priority 4 only: legacy proxy chains from the matrix's "yes" rows
     (HAProxy ≤ 2.4, older F5/Citrix/Squid/ATS, custom Python/Go proxies)
```

The fingerprint check (§4) decides which transport a given target even gets, so it
runs before either. A `Server:` header of `nginx/1.21+`, `Caddy` or `envoy` means the
raw-socket path is a waste of budget on that host regardless of what the matrix says
about its partial H2 columns.

`recon send` is an HTTP client and normalises by design; it cannot do either.

### The shared primitive

**The race plan and this plan need the same dependency.** Race conditions need h2
frame withholding; smuggling needs h2 frame construction. Both need raw socket
control for their HTTP/1.1 fallbacks.

Proposal: one module, `recon/transport.py`, providing

```
raw_request(host, port, tls, raw_bytes, read_responses=N) -> [responses]
h2_request(host, frames, withhold_final=bool) -> [responses]
```

wrapped in the existing scope / allowed-methods / rate / budget enforcement. Built
once, it unblocks plan4 row 15 (burst executor) and row 22 (raw socket executor)
together. That is a materially better trade than building two one-off executors.

Until it exists, cases from `hs-confirm` onward record `blocked` with the reason —
the precedent AGENTS.md already sets for SSRF depth branches. The operator lane is
Burp's **HTTP Request Smuggler** extension and Turbo Intruder (HackTricks ships
scripts for both at L393-481), outside recon enforcement and under
`burp-workflow.md` approval.

---

## 10. Case ladder

| Case | Established | Needs executor |
|---|---|---|
| `hs-topology` | hop structure: front-end present, protocol accepted, downgrade behaviour, connection reuse | no |
| `hs-fingerprint` | the proxy/CDN and version identified (mind-hunt's quick-check) | no |
| `hs-suitability` | which technique family the topology admits (§4 priority order) | no |
| `hs-timing` | a boundary disagreement is indicated by a self-only timing differential | **yes** |
| `hs-confirm` | the disagreement is confirmed on a connection you hold, with a differential response | yes |
| `hs-direction` | which hop uses which header — CL.TE vs TE.CL vs H2.CL vs 0.CL | yes |
| `hs-prefix` | a smuggled prefix is accepted and affects a subsequent request on your own connection | yes |
| `hs-impact` | the prefix achieves something: control bypass, request capture, rewriting disclosure, cache poisoning | yes |
| `hs-window` | the poison window measured — how long and how many requests | yes |

Three of nine are offline, and they are the three that decide whether the rest is
worth attempting. `hs-topology` through `hs-suitability` produce a ranked,
technique-assigned target list with no malformed request sent at all.

---

## 11. Chaining — smuggling is an amplifier

HackTricks devotes five sections to this and it is where the severity lives.

```
outbound
  http-smuggling -> access-control   bypass front-end controls              (L186)
  http-smuggling -> info-disclosure  reveal front-end request rewriting     (L222)
                                     internal headers, routing, client IP
  http-smuggling -> pii-exposure     capture other users' requests          (L246)
  http-smuggling -> xss              turn reflected XSS into delivered XSS  (L272)
  http-smuggling -> open-redirect    on-site redirect becomes open redirect (L298)
  http-smuggling -> cache-poisoning  poison the edge cache                  (L332)
                                     — the single biggest multiplier
  http-smuggling -> cache-poisoning  cache deception variant                (L362)

inbound
  cache-poisoning -> http-smuggling  mind-hunt's Akamai hop-by-hop case: the edge
                                     cache and the desync compound
```

The `http-smuggling → cache-poisoning` edge matters most: a desync that poisons a
shared cache entry converts a per-connection bug into a persistent one affecting
everyone. mind-hunt's cache skill already names the Akamai hop-by-hop → edge
poisoning case from the other direction, so the two classes meet.

`cache-poisoning` is the class the cache plan proposes; `pii-exposure` is the PII
plan's. Both are prerequisites for the full chain set here.

---

## 12. Class and seeding

```python
# topology is the signal — a front-end that downgrades is the modern precondition
if front_end_present and http2_accepted:
    out["http-smuggling"] = "HTTP/2 front-end: check upstream downgrade (H2.CL/H2.TE)"
elif front_end_present:
    out["http-smuggling"] = "proxy chain on HTTP/1.1: CL.TE/TE.CL/TE.TE candidate"
elif post_body_accepted:
    out.setdefault("http-smuggling",
                   "single origin: CL.0 / client-side desync candidate")
```

Then `"http-smuggling": ("hunt-http-smuggling",)` in `skillmap.py`.

`http-smuggling` already exists as a corpus label with 89 rows, so unlike the cache
and PII classes this one needs no new vocabulary in `build_dossiers.py`.

---

## 13. Implementation shape

### `recon/transport.py` — the shared executor (§9)

Built once, serves plan4 rows 15 and 22. Two layers, and the order is load-bearing
(§9):

| Layer | Need | Serves |
|---|---|---|
| `h2_frames` | frame-level h2: explicit `content-length`, CRLF in header values, pseudo-header control, no length recalculation on downgrade | **primary** — H2.CL/H2.TE (§4 priority 1) and the race plan's single-packet withhold |
| `raw_h1` | byte-exact HTTP/1.1: conflicting CL, obfuscated TE, no header fixing or auto-chunking | legacy only — §4 priority 4, the matrix's "yes" rows |

`h2_frames` is the shared surface with the race plan: smuggling needs frame
*construction*, single-packet needs frame *withholding*, and both need the same
control over when bytes leave. `raw_h1` is smuggling-only.

### `recon/smuggle.py` — profile plus ledger

```
smuggle_topology(host PRIMARY KEY)
  front_end, front_end_version, protocols_accepted,
  downgrades_upstream, downgrade_basis,
  connection_reuse, reuse_basis,
  normalises_te, strips_hop_by_hop, h2c_reachable,
  origin_reachable_directly,
  suitability,            -- json: which technique families this topology admits
  updated

smuggle_surfaces
  id, asset_id, origin, route, method, role,
  distinctive_response, body_accepted, discovery_basis, created, updated
  role: probe | differential | victim

smuggle_case_events
  id, topology_host, surface_id, case_id, technique, state, attempt_kind,
  own_connection,          -- boolean; false must be rare and justified
  timing_baseline_ms, timing_observed_ms,
  responses_read,          -- how many responses came back on one connection
  prefix_shape, window_requests, window_seconds,
  response_ref, control_response_ref, replay_artifact,
  note, created
  technique: cl.te | te.cl | te.te | h2.cl | h2.te | cl.0 | 0.cl |
             client-side | pause-based | h2c
```

`own_connection` is the §7 discipline made auditable: a run with `own_connection =
false` events is a run that was firing at shared pools, and the `own-connection`
eval checks it.

`timing_baseline_ms` / `timing_observed_ms` make `hs-timing` a single-row fact, and
`responses_read` is the cleanest confirmation signal — two responses on one
connection where one was sent.

### `recon/fingerprint.py` additions

```python
PROXY_SIGNATURES        # Via, X-Served-By, X-Cache, Server variants per CDN/proxy
protocol_support(host)  # h1.1 / h2 / h3 accepted; ALPN read
downgrade_indicator(h2_response_headers)   # artifacts of an h1 upstream hop
```

`downgrade_indicator` is the highest-value addition: it answers the one question
that decides the whole hunt, and it is readable from an ordinary HTTP/2 response.

### CLI

```
recon smuggle topology <campaign> [--host H]   hop structure + suitability
recon smuggle surface  <campaign>              probe / differential / victim roles
recon smuggle plan     <campaign> --host H     technique-assigned case cards
recon smuggle record   <campaign> --case C --technique T --state S ...
recon smuggle status   <campaign>              topology + ladder per host
recon smuggle verify   <campaign> --event N    re-check on a fresh connection
```

---

## 14. Proof binding

`factcheck.py` accepts `status_is`, `header_present`, `header_equals`,
`body_contains_raw`.

| Case | Binding |
|---|---|
| `hs-topology` | `header_present` on proxy signatures; ALPN and protocol facts recorded |
| `hs-timing` | `timing_observed_ms` against `timing_baseline_ms`, with the well-formed request as `control_response_ref` |
| `hs-confirm` | `responses_read > 1` on a single connection, with both responses stored |
| `hs-direction` | the differential target's response changing under one technique and not its inverse |
| `hs-prefix` | `body_contains_raw` on a unique marker from the smuggled prefix, appearing in **your own** follow-up response |
| `hs-impact` | per impact — `status_is` on a bypassed control, `body_contains_raw` on a captured value or a poisoned cache entry |
| `hs-window` | `window_requests` and `window_seconds` observed |

`hs-prefix` is the proof that matters and it is entirely self-contained: your marker,
your connection, your second request. A triager replays two requests and sees the
prefix land.

Per ARTEX doctrine: measured impact with a denominator — "the smuggled prefix
affected 3 of 3 follow-up requests within an observed 8-second window" — plus the
proof basis.

---

## 15. Wiring

```
.claude/skills/hunt-http-smuggling/SKILL.md
.claude/skills/hunt-http-smuggling/references/{topology.md,techniques.md,blockers.md,sources.md}
.claude/skills/hunt-http-smuggling/evals/{topology-first,own-connection,technique-declared,timing-before-malformed}/
recon/transport.py          shared raw-socket + h2 frame executor (§9)
recon/smuggle.py            topology profile + two tables
recon/fingerprint.py        proxy signatures, protocol_support, downgrade_indicator
recon/score.py              http-smuggling seeding rule (§12)
recon/catalog.py            HUNT_SKILLS entry
recon/skillmap.py           "http-smuggling": ("hunt-http-smuggling",)
recon/findings.py           seven outbound + one inbound chain row (§11)
recon/chain.py              the smuggling -> cache-poisoning amplification chain
recon/cli.py                smuggle verb group
tests/test_recon_smuggle.py
tests/test_recon_transport.py       raw-byte construction + h2 frame fixtures
AGENTS.md                   http-smuggling bullet
Handover.md                 transport.py and smuggle.py rows
```

Gate: discover over `tests`, green at 511+.

---

## 16. Evals

**`topology-first`** — any case from `hs-timing` onward recorded without
`hs-topology` and `hs-suitability` for that host must fail. Testing CL.TE against an
HTTP/2-end-to-end target is how the budget disappears.

**`own-connection`** — an event with `own_connection = false` and no recorded
justification must fail. §7: probing shared pools makes your own noise
indistinguishable from a finding.

**`timing-before-malformed`** — a `hs-confirm` on a host with no `hs-timing` event
must fail. The timing probe is the primary method, not a formality.

**`technique-declared`** — an event without `technique` set to one of the ten values
must fail. "Smuggling works here" without naming CL.TE versus H2.CL versus 0.CL is
not reproducible, and the remediation differs completely.

---

## 17. Pipeline

```
LOCAL="ollama/hf.co/huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF:latest"   # CONTEXT 131072
FB="opencode/deepseek-v4.1-flash-free"
MERGE="anthropic/claude-opus-5-5"
DRAFT="codex exec"
```

| Stage | Runner | Fallback |
|---|---|---|
| 0 — audit fingerprint.py, and the race plan's executor overlap | none | — |
| 1 — source packs (split, below) | none | — |
| 2 — draft | `codex exec` | `$FB` |
| 3 — adversarial review, cited JSON | `$LOCAL` | `$FB` |
| 4 — citation validation, rank, top 3 | none | — |
| 5 — merge + wiring | `$MERGE` | `codex exec` |
| 6 — gate: test suite | none | — |

### Pack contents — split, because HackTricks alone is ~100 KB

```
pack.shared.md     (~12 KB) the boundary-disagreement model, §4 priority order,
                            house template, integration contract, transport spec
pack.classic.md    (~16 KB) shared + HackTricks README L20-110 (theory/reality,
                            CL.TE/TE.CL/TE.TE), L111-183 (timing, probing,
                            hop-by-hop), L186-390 (the impact sections)
pack.modern.md     (~18 KB) shared + Kettle 2021/2022/2025 summaries, the 2026 0.CL
                            follow-up, HackTricks request-smuggling-in-http-2-
                            downgrades.md + browser-http-request-smuggling.md,
                            mind-hunt L36-71 (suitability matrix + H2 vectors)
```

Shared block **first and byte-identical** in both, so the llama.cpp prompt cache
prefills it once. At ~49 tok/s: shared ≈ 60 s, then ≈ 80 s and ≈ 90 s — versus ~4 min
for one combined pack, and HackTricks' six files would not fit at all.

**Do not pack HackTricks' Turbo Intruder scripts (L393-481)** — they are operator
tooling, not method, and they inflate the pack for no review value.

Configured: `providers.ollama.settings.headerTimeout` 1,800,000 ms (30 min),
`timeout` 3,600,000, `chunkTimeout` 300,000, `OLLAMA_KEEP_ALIVE=4h`.

### Stage 3 review contract

1. Which topology facts or technique families does the draft miss?
2. Which blockers in §8 lack a defeat path?
3. Where does the draft assume a proxy chain when the 2022/2026 single-server classes
   apply?
4. Where does the draft send a malformed request before a timing probe would have
   answered the same question?

```json
{"axis":"...","claim":"...","source_file":"...","line_start":0,"line_end":0,"why_missing":"..."}
```

Axes: topology discovery · suitability assignment · timing detection · technique
breadth · blocker defeat · prefix proof · window measurement · chain amplification.

---

## 18. Build order

1. **`downgrade_indicator` + `protocol_support` + `PROXY_SIGNATURES`** in
   `fingerprint.py`, plus the `Server:` header quick-check (§4) as `hs-fingerprint`.
   Together they answer the question that decides everything else, and the
   quick-check is one HEAD request — the cheapest step in the whole class.
2. **`smuggle_topology` table and `recon smuggle topology`** — the suitability
   assignment. Still no malformed request sent.
3. **`recon/transport.py`** as its own bounded project, inside scope/rate/budget
   enforcement. **`h2_frames` first, `raw_h1` second** (§9) — built in the other
   order it cannot reach the targets the matrix says are live. **Coordinate with the
   race plan**, which needs the same h2 frame control for single-packet.
4. `recon/smuggle.py` ledger — schema, class, CLI, tests as four separate writes.
5. Timing detection (`hs-timing`) first, on the executor.
6. Confirmation and direction, then prefix and impact. Impact needs the **second
   client you also control** (§7) — a second session, a second IP, or an anonymous
   fetch you issue — so `attempt_kind` and the two response refs land with it, not
   after it.
7. Chain rows and the smuggling → cache-poisoning amplification chain (§11), after
   the cache plan lands its class.

Steps 1-2 and 4 touch no target. Step 5's probes are self-only by construction.

---

## 19. Other sources — what they contribute

### ARTEX — nothing

`"request smuggling"`: **0**. The seven `Transfer-Encoding` hits are its own
`traffic/replay.go`, `traffic/rewrite/rule.go` and `web/src/lib/replay.ts`. One
`desync` hit in `agent/toolrag.go`.

### PentAGI — nothing

`"request smuggling"`: **0**. The eight `desync` hits are frontend code —
`chunk-reload.ts`, `storage-keys.ts`, `route-error` — using the word in a UI sense.
**Tenth category with no contribution.**

### BugBountySkills — the least hollow folder yet, still not usable

| File | Lines | Domain markers |
|---|---|---|
| `theory.md` | 73 | 3 |
| `hunting-methodology.md` | 86 | **3** |
| `bypasses.md` | 117 | **9** |
| `payloads.md` | 209 | **9** |

24 markers across 485 lines, searched for `Transfer-Encoding`, `Content-Length`,
`CL.TE`, `TE.CL`, `chunked`, `desync`, `front-end`, `back-end`, `smuggl`.

This is the **first folder of ten that is not a complete shell** — `bypasses.md` and
`payloads.md` carry some genuine content. But `hunting-methodology.md` at 3 markers in
86 lines is still empty, and 9 markers across 209 payload lines is thin for a class
defined entirely by two header names. Verdict: payload fragments may be worth a
glance; the methodology is not. **Ten folders read, nine shells and one marginal.**

---

## Sources

- https://portswigger.net/kb/papers/z7ow0oy8/http-desync-attacks.pdf — 2019
- https://portswigger.net/research/http2 — *HTTP/2: The Sequel is Always Worse*, 2021
- https://i.blackhat.com/USA-22/Wednesday/us-22-Kettle-Browser-Powered-Desync-Attacks-wp.pdf — 2022
- https://portswigger.net/research/http1-must-die — *HTTP/1.1 Must Die: The Desync Endgame*, 2025
- https://i.blackhat.com/BH-USA-25/Presentations/US-25-Kettle-HTTP1-Must-Die-The-Desync-Endgame-wp.pdf
- https://portswigger.net/blog/http-1-1-must-die-conquering-the-0-cl-challenge — 2026 follow-up
- http1mustdie.com — whitepaper, toolkits, remediation guides
- https://portswigger.net/web-security/request-smuggling — Academy topic and labs
- https://github.com/b4rdia/HackTricks/tree/master/pentesting-web/http-request-smuggling
- https://github.com/b4rdia/HackTricks/blob/master/pentesting-web/h2c-smuggling.md
- https://github.com/b4rdia/HackTricks/blob/master/pentesting-web/http-response-smuggling-desync.md
- https://arxiv.org/pdf/2503.10846 — WAFFLED, the parsing-discrepancy generalisation
- https://github.com/BaaRai/ARTEX — zero
- https://github.com/vxcontrol/pentagi — zero
- https://github.com/0xN0RMXL/BugBountySkills — `HTTP_Request_Smuggling/`, marginal
- mind-hunt (local, MIT, © 2026 MindflareX) — `skills/hunt-http-smuggling/SKILL.md`,
  SHA-256 `9b2bac1800746f1e987fcebd3790709401a25c68e9249fa6eeaeafbe1219e674`.
  **Imported:** the Target-Suitability Matrix (L36-53) into §4, the operator
  fingerprint quick-check (L54-63) into §4, the H2-first transport correction
  (L68) into §9, and the cross-client impact gate (L79) into §7. Its sibling
  `skills/hunt-cache-poison/SKILL.md`, SHA-256
  `70809f2b64d04ea30f376b430e391e5d96fb0f5a30614a27014a268720fad390`, states the
  same gate at L224 and L230 and is the reference for the §11 cache chain.
  **Not imported:** its CL.TE worked example (L9-19), superseded by HackTricks §5;
  its chain prose (L72-81), already covered by §11 with ledger bindings.
