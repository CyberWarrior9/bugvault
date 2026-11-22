# RCE hunting: sink-led, proof-gated build plan

**Status:** revised 2026-11-20; offline/owned-lab infrastructure **partially
implemented**. `recon/rce.py`, `recon/execproof.py`, the two sink taxonomies,
CLI, routing, skill, report section and tests exist; no scanner, payload
generator, target executor, campaign authorization or live RCE proof exists.
Existing BugVault skills remain authoritative for their entry surfaces. The
earlier source-survey draft is preserved
**unchanged** at [research_notes/RCE hunting plan 2026/rce-legacy-draft.md](../research_notes/RCE%20hunting%20plan%202026/rce-legacy-draft.md).
It contains exploratory techniques and superseded proof/impact proposals; it is
**not** an execution runbook. Its previous header said 2026-11-21, a future date
relative to this revision, so the original drafting date is not established.

This plan merges the draft's sink-specific architecture and technology inventory
with the [research-backed RCE hunting plan](../reports/RCE%20hunting%20plan%202026.md)'s
authorization, source-to-sink, lab and evidence gates. It does not add permissions
to `scope.json` or authorize contact with a target, callback receiver or provider.

## 1. Decision and measured basis

**RCE is a terminal outcome, not a host-wide scan class.** A candidate starts at
an exact remotely controlled input and a plausible *server-side* sink. It becomes
RCE only when the program-defined attacker role can make that sink execute code
or an OS command outside the intended privilege boundary, with independently
attributable evidence. A normal administrator invoking an intended job, client-side
JavaScript, template arithmetic, a file being converted, a serialized-looking
cookie, a fetched URL and a callback do not by themselves meet that definition.

The local `vault/_data/reports-merged.csv` has 15,443 rows: 650 labelled `rce`,
0 `ssti`, 14 `file-upload` (verified by counting the `class` column). Those labels
do **not** show that every SSTI report or most upload execution was reclassified
as RCE. The older draft's payout/subtype statistics are exploratory, sample- and
taxonomy-dependent; manually review underlying reports before treating them as
frequency, probability, severity or bounty forecasts. Do not rank by a copied
report title or the mere presence of a known CVE.

**Keep from the original draft:** two candidate classes, `command-injection`
and `deserialization`, on *qualified sink paths*; a shared, offline execution-proof
contract; typed evidence roles; direct/indirect channel distinction; explicit
lab-only tiers; and technology-specific questions when the technology is actually
observed. **Improve:** event semantics, transitive source/worker provenance,
case-specific authority, false-positive controls, measured timing, receiver
approval and independently verified cleanup. **Do not adopt:** a payload/bypass
library, unconditional format-marker seeding, automatic finding promotion,
callback-as-execution, a universal proof score, or sensitive-file/environment
reads as a mandatory impact demonstration.

## 2. Current boundary: installed versus proposed

| Installed now | What it does **not** establish |
|---|---|
| `recon/fields.py`, HAR/Burp/OpenAPI imports and `recon/jsledger.py` inventory routes, names, frontend references and some captured propagation. | Server-side transitive caller reachability or arbitrary backend sink execution. Ordinary HAR/Burp projections deliberately discard cookie/header values and most body values; do not silently scan private raw exports. |
| `recon/ssti.py` / `hunt-ssti` classify bounded arithmetic/literal contrasts on specific raw render surfaces. | Engine identity, sandbox escape, OS execution or severity from arithmetic alone. `ssti.depth_grants` gate offline evidence recording, not an execution sender. |
| `recon/upload.py` / `hunt-file-upload` distinguish `accepted`, `stored`, `reachable`, `processed`, `served`, `executed`, `effect`; `executed` needs an attributable consumer log and separate effect/replay/control artifacts. | An upload runner, permission for live active files, or semantic proof that every marker/log really represents code execution. Existing no-executable/no-polyglot/no-configuration-override limits remain in force. |
| `recon/ssrf.py`, `recon/callbacks.py`, SSTI/upload callback handling validate some approved receivers and recorded interactions. | A generic pre-send check of every embedded destination or an assertion that a DNS/HTTP contact equals RCE. Do not remove existing module-specific receiver checks. |
| `recon/factcheck.py` checks status, headers and raw body-byte predicates; `recon/findings.py` requires distinct replay/negative artifacts for `confirmed`; `recon/chain.py` orders confirmed *class findings*. | Timing measurements, semantic verification of replay/control, or proof of execution from the name `ssti-exec`. `recon/store.py` stores no measured request duration. |
| `recon/rce.py`, `recon/cmdi.py`, `recon/deser.py` and `recon/execproof.py` keep private source-supported candidate paths and operator-supplied offline/lab receipt contrasts, with exact endpoint-class routing, hash/policy review and bounded sanitized views. | Source/worker truth, deployed reachability, target execution, actual actor authority, benign-transformation discrimination or independent semantic validation. A syntactically eligible lab receipt is **not** RCE. |

`rce` is an outcome/finding label, **not** an automatically seeded coverage row.
Existing entry-path skills own their own checks; `hunt-rce` shares terminal-proof
rules without weakening their gates. The `command-injection` and `deserialization`
classes and `recon rce declare|record|show|status|verify` are runnable **offline**;
the later ranking, deeper reachability checks and live handoff remain proposals.

## 3. What and where: exact input-to-sink worklist

For each candidate, record an **exact** operation (URL, method, input location,
representation), program-defined actor/account/role/tenant/workflow, controlled
value class, validation and decoding, persistence/queue hops, trigger, deployed
consumer/worker/configuration, sink, execution authority, effect channel and
cleanup owner. Give each edge a source kind (capture, authorized source, owner log,
lab), file/line or request/log reference, SHA-256, timestamp, capture completeness,
scope revision and `direct`/`inferred`/`unknown` status. Follow transitive callers
and fork the graph for each consumer; one safe branch does not clear another.
Authorized server source and CodeQL/Semgrep findings are optional: black-box
campaigns must not pretend to have source or owner logs they were not given.

| Candidate path | First discriminator and existing owner |
|---|---|
| **Process and argument injection**: exports, reports, conversion, mail, backup, search, filenames and job options reaching a subprocess or its arguments. | Authorized source or owner/owned-lab worker record distinguishes inert data, interpreted options and an actual controlled command. New `command-injection` candidate; upload-process-argument cases remain review/lab-only under `hunt-file-upload`. |
| **SSTI and template includes**: authored templates, delayed email/export/CMS renders and include selection. | Compare literal and harmless evaluated controls on the same *server* surface; then identify the deployed render context. `hunt-ssti` retains the entry proof. |
| **Unsafe deserialization/lookup**: session, request, hidden state or queued message reaching a deployed deserializer. | Verify byte control, integrity checks, consumer/version and effective allow-list before inferring a sink. Format signatures are leads only. Memory corruption and gadget chains are lab-only. |
| **Upload → processor/interpreter**: media, documents, archives, preview, signed-storage finalize and retrieval. | Track intake, storage, worker processing and actual execution as distinct stages; inspect effective policy and owner/owned-lab consumer evidence. `hunt-file-upload` owns the lifecycle. |
| **Direct server evaluation**: transformation rules, report designers, automation expressions and build features. | Establish a *backend* evaluator and reachable lower-trust input. `eval` in a browser bundle is not a backend sink; `hunt-js-bundle` supplies static leads only. |
| **Archive/XML/document transformation**: parser, XSLT, document converters and delegates; only evaluate SSI/ESI or formula/LaTeX if the actual renderer is identified. | Separate parse, read, transform, process launch and effect edges; route XML entry to `hunt-xxe`, file intake to `hunt-file-upload`. No active documents, archive bombs or traversal tests on a live target under the present skill. |
| **SQLi/SSRF/XXE → second executor**: a separately proved initial primitive leading to a specific database facility, internal job or parser-to-process hop. | Prove each trust boundary, exact next-hop destination/method/authority and terminal effect separately. Existing `hunt-sqli`, `hunt-ssrf` and `hunt-xxe` grants apply; no inference from an error or callback. |
| **Debug/admin/CI/CVE preconditions**: exposed job editor, runner or debug feature under the *actual lower-privileged role*. | Distinguish intended privileged use from an authorization flaw; verify deployed version/configuration and route through `hunt-access-control`, cloud trust and `recon/vulnintel.py` as appropriate. No production build triggers or credential derivation by default. |

**Ranking, not severity or permission:** score an exact path/context 0–3 for
direct input-to-sink evidence, 0–2 for attacker-role reachability, 0–2 for
verified deployed version/configuration, 0–2 for an independently attributable
and safe observation channel, and 0–1 for fresh corroboration. Review 7–10
first; at 4–6 list the missing precondition; at 0–3 park a sourced hypothesis.
Unknown earns zero. An exclusion or missing permission vetoes live work at **any**
score. Reopen on changed source/route, worker, role, configuration, receiver grant
or cleanup state—not a repeated static signature. This is a proposed heuristic,
not a measured probability model or endpoint-wide coverage claim.

## 4. Evidence contract: what a result means

The **proposed** semantic ladder remains: `lead` → `reached-sink` → `behavior-observed` →
`server-execution-supported` → `impact-proven`. `blocked`, `inconclusive` and a
variant-specific `negative` remain possible at every rung. The installed journal
uses `blocked`, `inconclusive`, `negative`, `observed` and `execution-claimed` as
operator-declared observation states, assessed at most as `eligible-for-validator`
for owned-lab receipts. It does **not** implement those semantic rungs or BugVault
finding stages. Do not map a borrowed PoE number,
an extracted file, or an operator assertion directly to `confirmed`.

- **Lead:** a signature, known-CVE match, code-query hit, suspected sink or
  scanner report. Mark `static-analysis-unexecuted` when based only on source.
- **Reached sink:** the *controlled* input crosses an identified server/worker
  boundary under the relevant actor and deployed configuration; preserve the
  actual source/log/capture chain. A parser error or DNS lookup can support this
  rung but can also have another cause.
- **Behavior observed:** name only the effect actually seen—evaluation, parsing,
  processing, delay, lookup or callback. A status code, marker reflected from the
  request, thumbnail or successful upload is not proof of code execution.
- **Server execution supported:** after specific written permission, a minimal
  one-shot, nonpersistent, **server-only** owned effect not simply supplied in the
  request, attributable to the sink/worker, plus a healthy baseline, fresh replay
  with another nonce and a matched negative whose assertion fails. Direct output
  or owner/owned-lab worker evidence can support attribution; a callback or slow
  request **alone**, even with a derived-looking label, cannot. The independent
  validator—not the ledger—decides whether BugVault's `confirmed` gate is met.
- **Impact proven:** a separate authorized, narrow, owned consequence and readback.
  Never require system-file reads, environment dumps, cloud metadata, secrets,
  persistence or broad lateral access merely to claim higher severity. A limited
  container or low-privilege worker may reduce impact; measure actual authority.

The installed offline/lab receipt has typed roles: `baseline`, `trigger`, `verification`
(fresh replay), `negative-control`, `positive-control` (healthy workflow),
`effect`, optional `impact`, and `cleanup`. Bind each to exact case, actor, owned
object and worker labels, attempt timestamps, source and hash, scope/policy
snapshot and declared body fidelity. Real native request IDs and separately
verified Burp/operator references remain **future work**; the journal has no
live import or verifier for them.
Two different hashes or a byte quote do not establish causal semantics. Missing,
truncated, unsupported-encoding, unowned or stale evidence yields `inconclusive`/
`not-assessed`, never automatic promotion. Keep secret-bearing originals private;
expose a minimal redacted model-facing view.

## 5. When: gates, deliverables and acceptance

| Phase | Deliverable | Must pass before the next phase |
|---|---|---|
| **P0 · Written authority** | Program URL/rules, exact operations/methods/actors, exclusions, mode, total rate/time/request/byte/object cap, approved receiver/second hop, disposable owned resources and cleanup owner. | Existing `scope-policy` and campaign `scope.json` match the **specific** proposed action. A standing written plan may approve a bounded series of actions; absence of execution permission or a connected observer means offline/lab-only. No grant label alone authorizes target traffic. |
| **P1 · Source-qualified inventory** | Exact input→transformation→trigger/worker→sink graph and uncertainty/provenance; eight-path worklist and ranking. | No general `rce` row, no automatic promotion from signatures, no pooling contexts or unsupported source assumptions. Preserve out-of-scope second hops as gaps. |
| **P2 · Owned-lab discrimination** | Loopback fixtures for a normal operation, safe contrasting case, fixed negative and deferred worker (when applicable), with inert nonpersistent effects. | Deliberately defeat reflection, client-only script, file conversion, deserializer errors, incidental callbacks and background latency as false positives. No target or external egress. |
| **P3 · Offline evidence infrastructure** | Additive assessor, source-qualified `command-injection`/`deserialization` candidate ledgers, explicit routing, bounded review statuses, hash/policy verification, tests and catalogue entries. | Tools neither send traffic nor generate payloads/promote findings. Keep existing upload/SSTI acceptance intact until comparative regressions pass; missing timing/receiver instrumentation stays `blocked`. |
| **P4 · Optional supervised campaign handoff** | One reviewed case run sheet naming exact owned workflow, least-impact allowed effect, request/channel accounting, receiver, observer, stops and cleanup. | Written scope/execution plan and appropriate method/budget approved, connected dedicated browser through Burp (or separately approved scoped native path), and all second hops/receivers approved. Burp/scanner requests require manual shared accounting. **P3 does not authorize P4.** |
| **P5 · Independent disposition** | Source-bound baseline, trigger, replay, negative, healthy control, effect, any separately permitted impact, cleanup and validator decision. | `confirmed` only after human review of remote reachability, actual execution and causality; `impact-proven` only for demonstrated allowed impact. One failed retest does not prove a fix without a working healthy control. Keep blocked/inconclusive history. |

**Stop and preserve evidence** on 429/5xx, challenge/lockout, degradation,
unexpected cost or side effects, real-user/third-party data, unapproved redirect
or embedded destination, lost receiver, exhausted cap, worker uncertainty or
unresolved cleanup. Delete/abort owned objects and queued jobs where permitted;
record readback or retention status before operator-approved resumption. Do not
switch to Burp, native HTTP or a scanner after a failed gate. No web/reverse
shells, executable uploads, malicious gadgets, parser bombs, destructive writes,
credential exfiltration or persistence in this plan. Preserve the current
`hunt-file-upload` hard limits; a different written program exception and safety
review would be a separate decision, not an implication of this document.

## 6. Offline implementation slices (partly installed)

Current P1/P3 slice: `recon rce declare` records up to twelve typed edges and
requires an exact in-scope endpoint, captured/owner route source, method/path
variant, direct edges including the sink and a source/owner/lab basis to seed
candidate-class `untested` coverage. `record` stores only offline or owned-lab
evidence, rechecks sink/source/policy and assesses bounded controls without
contacting a target. Its strongest result is `eligible-for-validator` and its
report/CLI views expose origin and value-free hashes rather than raw query values,
source excerpts or account labels. The loopback tests contrast reflection,
deferred worker echo and parser rejection without running code or using an
external network. These are **software tests**, not RCE proofs.

The numbered items below record both the original proposed slices and what is
still missing. No live execution is implicitly authorized by an installed CLI.

1. **Shared contract before new classes (partial):** `recon/execproof.py` is a
   pure offline syntactic assessor of operator-supplied roles, declared capture
   fidelity, marker contrasts and attempt ordering. `recon/rce.py` binds a
   receipt to its source-qualified sink, actor/worker labels, owned-object label
   and policy/artifact hashes. It returns `eligible-for-validator` or an explicit
   `blocked`/`negative`/`inconclusive`/`behavior-observed` assessment, never
   independently established execution or a finding. There is no generic
   measured-duration assessor or shared live-evidence manifest. Keep existing
   `recon/upload.py` and `recon/ssti.py` gates unchanged until any comparative
   refactor passes all regressions.
2. **Source-qualified candidate inventories (partial):** `recon/cmdi.py` and
   `recon/deser.py` provide sink-kind taxonomies; `recon/rce.py` records the exact
   operation/field/consumer and operator-labelled evidence path. Automated source
   dataflow, deserializer integrity/configuration checks and deployed reachability
   are **not implemented**. An operator can declare an unqualified static lead;
   no passive-signature auto-extractor or auto-seeding is installed.
   Ordinary HAR/Burp field projections are value-free; any opt-in private raw
   review must retain redaction, source hashes, caps and operator permission.
3. **Routing and guidance (installed):** `command-injection` or `deserialization`
   is seeded only from a source-supported exact sink; seeder, coverage route,
   catalogue, tests and `hunt-rce` terminal-proof guide are installed. Narrower
   class skills await their ledgers and regression fixtures.
   Do not create a catch-all `rce` coverage row or claim that a `js-bundle` eval
   reference is a backend sink. Keep `ssti-exec` a chain *name* until an actual
   execution-proof step is available; confirmed SSTI is not that step.
4. **Optional channels, after their primitives exist:** timing analysis needs
   trustworthy per-request duration, capture provenance, bounded baselines,
   jitter/health controls and clock semantics **before** a predicate is designed;
   `recon/store.py` currently records none. Some workflows already validate
   approved callback hosts *after* evidence capture (`recon/callbacks.py`);
   propose exact, structured receiver/second-hop declarations and pre-send
   enforcement for a future approved executor rather than claiming zero checks
   exist or pretending arbitrary payload strings can be parsed perfectly.
   Do not change native/Burp execution channels as part of an offline ledger.
5. **Hints only after proof:** add chain relations for an actual upload→processor,
   SSTI→subprocess or a separately granted second hop, bound to prior findings
   and the exact same owned workflow. No automatic metadata/credential chain or
   terminal RCE promotion from a source reference, callback or class label.

**Acceptance suite:** offline no-socket tests; actor/tenant/method/worker
non-merging; source/policy drift and tampered/truncated artifact rejection;
serialized-looking value without a reached sink; direct output versus reflection;
callback from a browser versus attributed server effect; slow baseline versus
measured timing; processed upload versus executed; SSTI arithmetic versus code
execution; matched replay/negative/healthy controls; lab-only tier; case-specific
receiver and second-hop block; unexpected third-party data/cleanup stop; and
existing upload, SSTI, SSRF, finding and chain regressions. Evaluation status is
local software correctness, **not** real CDN/runtime/target exploitability.

## 7. Research, rights and open decisions

The [research report](../reports/RCE%20hunting%20plan%202026.md) compares four
dated/content-rich repositories—[OWASP WSTG](https://github.com/OWASP/wstg),
[CodeQL](https://github.com/github/codeql),
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings),
[Semgrep rules](https://github.com/semgrep/semgrep-rules)—and four independent
publisher pages: [PortSwigger command injection](https://portswigger.net/web-security/os-command-injection),
[OWASP SSTI prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html),
[Microsoft deserialization guidance](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide),
and [ImageMagick security policy](https://imagemagick.org/security-policy/).
Repository commits indicate activity, **not** per-technique freshness. Use
source-qualified ideas and links; do not copy WSTG/third-party text, Semgrep
rules, HackTricks-fork material or ARTEX code into an MIT skill without a
separate license review. The archived survey's payload and bypass examples are
neither current policy nor required implementation deliverables.

Open before any pilot: written campaign authorization, actual source/worker
visibility, owned accounts and cleanup rights, deployed versions and policies,
an approved observation path/receiver, cross-channel accounting, and a validator
who can distinguish an intended privileged feature from attacker-driven server
execution. Until then the correct state is a scoped lead, **blocked**, or
**inconclusive**—never a confirmed target RCE.
