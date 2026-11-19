# Build plan — `hunt-xxe`

XML External Entity hunting for BugVault.
Drafted 2026-11-14. Target branch `recon-engine`. Baseline: 377 tests green.
Class `xxe` is already seeded by `recon/score.py:226` ("XML parsing surface") and
routes to no skill.

---

## 1. Corpus position

From `vault/_data/reports-merged.csv` (15,443 rows):

| Metric | XXE |
|---|---|
| Reports | 38 (0.25% of corpus) |
| Bounty rate | 45% (corpus average 43%) |
| Median | $900 |
| Mean | $1,600 |
| Max in corpus | $6,000 |
| Priced rows | 8 of 38 |

Rare but above-median yield. mind-hunt's framing holds: *"rare in modern stacks but
enormous when found — usually file-read + SSRF in one bug."* Known ceilings outside
the corpus sample: Twitter #248668 $10,080, QIWI #99279 $3,137.

Vault already holds 4 XXE dossiers in `vault/35-Report-Studies/`.

---

## 2. Source map

Seven sources assessed. Exact paths and anchors. Empty = contributes nothing.

### PortSwigger Web Security Academy — the authoritative current reference

| Take | URL |
|---|---|
| The canonical blind-XXE model: why parameter entities are required (they can only be referenced inside the DTD) | https://portswigger.net/web-security/xxe/blind |
| Classic retrieval, SSRF variant, surface discovery | https://portswigger.net/web-security/xxe |
| Local-DTD redefinition: error-based from *within* an internal DTD by redefining an entity declared in an external DTD | https://portswigger.net/web-security/xxe/blind |
| Named local DTD paths: `/usr/share/xml/fontconfig/fonts.dtd`, `/usr/share/yelp/dtd/docbookx.dtd`; Windows `file:///C:\Windows\System32\wbem\xml\cim20.dtd` | same |

Maintained, versioned, with labs. Use as the correctness baseline when sources
disagree.

### PayloadsAllTheThings — `swisskyrepo/PayloadsAllTheThings/XXE Injection/`

`README.md`, 688 lines, plus `Files/` and `Intruders/` directories.

| Take | Anchor |
|---|---|
| **Richest file-format inventory of any source** — SVG, SOAP, DOCX, XLSX, DTD | L475-644 |
| **XXE on JSON endpoints** as its own section | L453-474 |
| Error-based with local DTD, and with remote DTD, as separate sections | L218-297, L298-339 |
| Blind: basic, OOB, OOB with DTD + PHP filter, OOB with Apache Karaf | L340-426 |
| Detection section, ordered before exploitation | L50-77 |
| WAF bypass via character encoding | L429-452 |
| XInclude attacks | L148-156 |
| Classic base64-encoded retrieval; PHP wrapper inside XXE | L118-147 |
| Labs index | L645-659 |
| DoS section (Billion Laugh, YAML, Parameters Laugh) | L170-215 — **excluded from the ladder** |

`Files/` and `Intruders/` hold ready document artifacts — relevant to the
doc-upload surfaces.

### HackTricks — `b4rdia/HackTricks/pentesting-web/xxe-xee-xml-external-entity.md`

876 lines, 7 H2 sections, ~50 code blocks. Single file, no `xxe/` directory.

| Take | Anchor |
|---|---|
| **The blind/error mechanism taught as a model**, not payloads: stage-by-stage walkthroughs, and the constraint that *forces* the external-DTD design (nested entity definition is forbidden in an internal DTD) | L166-288, esp. L181-184, L231 |
| **Egress-blocked local-DTD path** with the spec loophole that enables internal redefinition, plus a DTD-path list and Docker-image DTD scanning | L233-308, L237-239, L294, L296-308 |
| **Inert "New Entity test"** — benign internal entity, substitution check, no file touched | L81-94 |
| Content-type conversion sections (urlencoded→XML, JSON→XML, Burp converter extension) | L485-539 |
| XInclude as the partially-controlled-document path | L441-453 |
| Hidden surfaces: SVG, PDF, Office Open XML, `jar:` / Java archives, SOAP, XLIFF, RSS, Java XMLDecoder | L310-539, L625-849 |
| Per-format sections SOAP / XLIFF / RSS / XMLDecoder | L625-849 |
| PHP wrappers for source read | L595-623 |
| Linked sibling: `pentesting-web/file-upload/pdf-upload-xxe-and-cors-bypass.md` | L481-483 |
| Tooling: dtd-finder (L294), xxexploiter (L853) | — |
| DoS section | L388-419 — **excluded from the ladder** |

### mind-hunt — `~/Downloads/mind-hunt/skills/hunt-xxe/SKILL.md`

120 lines, SHA-256 `a1d5d685ab3fb4a8c7060e98dd7eb0c1c03d62918a8871d773af626af578fc2e`.

| Take | Anchor |
|---|---|
| **8-surface "Where XXE Still Lives" list** | L10-20 |
| **The severity pitfalls** — "some servers fetch external DTD but refuse `file://` — you'll get blind SSRF, not file-read"; "/etc/passwd alone is Medium" | L109-114 |
| 6-step ordered test recipe, starting inert | L99-107 |
| WAF bypass set attributed to QIWI #99279: UTF-7, comment-injection inside the declaration, whitespace variation, parameter-entity nesting | L90-95 |
| 6 disclosed cases with bounties | L21-31 |
| Parser-default caution: modern Java/Python parsers default-secure; prioritise SOAP, SAML, RSS-import, doc-upload | L111 |

Disclosed set for the vault: Twitter #248668 ($10,080) · QIWI #99279 ($3,137) ·
Pornhub #72272 ($2,500) · QIWI #36450 ($1,000) · Bime #112116 ($750) ·
Uber #154096 ($500).

### ARTEX — `BaaRai/ARTEX`

| Take | Anchor |
|---|---|
| **Surface discovery as a numbered action**: "Content-Type tampering: JSON to XML to multipart (XXE where XML is accepted)" — the *how to find it* step no other source states | `skills/api-security/SKILL.md:77` |
| Proof doctrine: drive the route through; a filtered payload does not kill a route; measured impact with a denominator; proof basis executed-live / executed-lab / static-unexecuted; zero findings is valid | `agent/promptcatalog.go:42-82` |
| Phase ordering context (XXE sits in Phase 5, REST input validation) | `skills/api-security/SKILL.md:74-82` |

### PentAGI — `vxcontrol/pentagi`

Nothing. Two matches, both test fixtures: `backend/cmd/ftester/mocks/tools.go`,
`backend/pkg/tools/args_test.go`. XXE does not appear in its web-pentest prompt.

### BugBountySkills — `0xN0RMXL/BugBountySkills/KNOWLEDGE_BASE/XXE/`

Generated shell. `payloads.md` (143 lines), `hunting-methodology.md` (89),
`bypasses.md` (119) — 351 lines containing **zero** occurrences of `DOCTYPE`,
`!ENTITY`, `SYSTEM "` or `XInclude`. Metadata claims 14 reports, `$0` average.
Nothing usable.

---

## 3. Structure: rung × channel

The design insight from the source union. HackTricks documents four distinct exfil
paths, so **how evidence returns is a separate dimension from what was established.**

### Rungs — what is established

| Rung | Established |
|---|---|
| `xxe-surface` | an XML-consuming sink exists |
| `xxe-parse` | the parser processed our document (well-formedness differential, no entities) |
| `xxe-entity` | an **internal** entity expanded — entity processing proven, zero outbound traffic |
| `xxe-read` | attacker-chosen file content returned |
| `xxe-pivot` | an internal or metadata endpoint reached through the primitive |

### Channels — how evidence returned

| Channel | Egress | Mechanism |
|---|---|---|
| `in-band` | none | content reflected directly in the response body |
| `error-local` | **none** | content embedded in a parser error, using a DTD already on the target filesystem |
| `error-external` | yes | content embedded in a parser error, using an attacker-hosted DTD |
| `oob` | yes | two-stage external DTD; content leaves in a request to a controlled host |
| `blind` | yes | fetch observed, content not recovered |

**`xxe-read` is reachable on two channels with no egress at all.** That is the
practical headline: `in-band` and `error-local` prove arbitrary file read without a
single packet leaving the host, without a callback receiver, and without a grant.

mind-hunt L112 is the rung/channel distinction stated as a pitfall — a fetched DTD
with `file://` refused is `xxe-external` on the `blind` channel, not `xxe-read`.

---

## 4. Where to test — surface inventory

Union of mind-hunt L10-20, HackTricks L310-539/L625-849, PATT L475-644.

| `sink_kind` | Surfaces | Discovery |
|---|---|---|
| `declared-xml` | endpoints advertising `application/xml`, `text/xml` | `extract.py` content types; `specs.py` `spec_content_types` |
| `soap` | legacy enterprise APIs, `/soapserver/`, WSDL-described operations | path regex `soap\|wsdl`, `score.py:226` |
| `content-type-flip` | **JSON endpoints that also parse XML** | ARTEX `api-security:77`; PATT L453; HackTricks L485-539 |
| `doc-upload` | DOCX, XLSX, PPTX, SVG, EPUB, IPA, APK — zip-of-XML; `[Content_Types].xml`, `word/document.xml` | `score.py` `file-upload` seed + `fields.py` upload triggers |
| `saml` | SAML response parsing | class `saml` already seeded; `hunt-saml` exists |
| `feed` | RSS, Atom, OPML, SiteMap import | path/param vocabulary |
| `xmlrpc` | XML-RPC endpoints | path regex |
| `pdf-embedded` | PDF parsers handling embedded XML | HackTricks L477-483 |
| `xslt` | XSLT transformation inputs | HackTricks sibling `xslt-server-side-injection-*.md` |
| `jar-archive` | `jar:` protocol, Java archive handling | HackTricks L351 |

`score.py:226` already seeds class `xxe` on `\.xml$|soap|wsdl|xmlrpc` paths **or** any
asset whose observed content types include `xml`. The `content-type-flip` surface is
the one it cannot see, because nothing advertises it — that surface requires the
ARTEX discovery action.

---

## 5. How to dive in — attack first, structure after

The rungs in §3 are an **evidence model, not a running order.** Working them bottom
to top wastes requests: a successful direct read proves every rung beneath it in one
response. So lead with the attack and backfill the structure from what comes back.

### Entry: go straight for the read

```
1. PICK THE SINK        highest prior probability first, not inventory order
                        doc-upload  >  soap  >  content-type-flip  >  feed
                        >  saml  >  declared-xml  >  xmlrpc
                        (mind-hunt L111: modern Java/Python parsers default-secure,
                         so legacy and document surfaces outrank plain JSON APIs)

2. DIRECT READ ATTEMPT  one request: attacker-chosen path, in-band channel,
                        marker embedded so the response is attributable
                        - lands  -> you hold xxe-read immediately. Every lower
                                    rung is proven by the same response. Record
                                    them from it; do not re-probe.
                        - fails  -> go to 3. Do NOT conclude the sink is dead.
                                    (ARTEX promptcatalog:42-82 — "an initial
                                     setback does NOT mean the route is dead")

3. CLASSIFY THE FAILURE which of these happened?
                        a. no reflection, clean 200   -> channel problem, go to 4
                        b. parser error               -> error channel is open,
                                                         go to 4b, often faster
                                                         than in-band
                        c. payload rejected / stripped-> filter problem, §6 tree
                        d. request never parsed       -> wrong sink kind, back to 1

4. SWITCH CHANNEL       cheapest path to content, in this order
                        a. in-band        content echoed in the response body
                        b. error-local    content in a parser error via an
                                          on-disk DTD        [no egress]
                        c. error-external attacker-hosted DTD in the error
                        d. oob            two-stage external DTD
                        e. blind          fetch only, no content

5. DRIVE TO PIVOT       a read primitive is not the end of the route.
                        internal hosts, cloud metadata, and the fetch primitive
                        itself are the same bug continued. Do not stop at the
                        first file.

6. BACKFILL ONLY        drop to the inert ladder — well-formedness differential,
   WHEN AMBIGUOUS       then internal-entity substitution — only when steps 2-4
                        were all ambiguous and you need to know whether entity
                        processing is on at all before spending more requests.
                        HackTricks L81-94 · mind-hunt L101 · PATT L50-77
```

### Route portfolio

From ARTEX's doctrine (`agent/promptcatalog.go:42-82`), which is the strongest
attack-first material in the source set:

- Lay out **2-3 independent routes** across different sink kinds, ordered by how
  close each sits to impact — not by how easy it is to test.
- **Drive one route all the way through** before switching. A filtered payload, a
  404, an injection point with no echo: none of these kills a route.
- Mark a route **blocked** only when it is confirmed impassable, and reopen it when
  material new mechanics appear — a new surface, a new parser signal, a new
  credential.
- When a route yields — positive or blocked — return to the portfolio and take the
  next one.
- *"Better to drive one route all the way through and verify it than to shallowly
  scatter a pile of unverified suspects."*

Step 3 is the decision point no source makes explicit, and step 4 is what the
ledger's `channel` dimension records.

### Local DTD discovery (the `error-local` enabler)

- Known paths: `/usr/share/xml/fontconfig/fonts.dtd`,
  `/usr/share/yelp/dtd/docbookx.dtd` (PortSwigger); the longer list at
  HackTricks L294
- Windows: `file:///C:\Windows\System32\wbem\xml\cim20.dtd` (PortSwigger)
- Fingerprint-driven: derive candidate paths from the OS/distro signal in
  `recon/fingerprint.py`
- Image-derived: HackTricks L296-308 scans a matching Docker image for DTDs;
  `dtd-finder` (L294) automates it
- The mechanism: redefine an entity *declared in the external DTD* from within the
  internal DTD — PortSwigger states the constraint, HackTricks L237-239 explains the
  spec loophole that permits it

---

## 6. WAF and filter bypass — ordered fallback tree

HackTricks' bypass set is a flat list of four; mind-hunt's is four attributed to
QIWI #99279; PATT has one encoding section. **None is ordered.** This is the union,
as a decision tree keyed on what the block actually is.

```
probe blocked -> classify the block first  (recon/waf.py: allowed|stripped|blocked|modified|reset)

├─ DOCTYPE declaration rejected outright
│     -> XInclude path: no DOCTYPE required
│        HackTricks L441-453 · PATT L148-156
│     -> also the path when you control only part of the document
│
├─ DOCTYPE allowed, ENTITY declaration matched
│     -> parameter-entity nesting                      mind-hunt L95
│     -> comment injection inside the declaration      mind-hunt L93
│     -> whitespace / formatting variation              mind-hunt L94
│     -> numeric HTML-entity nesting to pull the DTD    HackTricks L573
│
├─ payload matched on byte content
│     -> character re-encoding: UTF-7, UTF-16, alternate declared encodings
│        HackTricks L551 · PATT L429-452 · mind-hunt L92
│
├─ `file://` refused but external fetch succeeds
│     -> language wrappers (PHP filter / expect)        HackTricks L567, L595-623
│     -> `jar:` / archive protocol                      HackTricks L351
│     -> if nothing reads: this is xxe-external on the `blind` channel,
│        not xxe-read -> pivot to class `ssrf`           mind-hunt L112
│
├─ egress blocked entirely
│     -> error-local channel: local-DTD redefinition
│        HackTricks L233-308 · PATT L218-297 · PortSwigger
│
├─ content type restricted to JSON
│     -> content-type flip / JSON→XML conversion
│        ARTEX api-security:77 · PATT L453-474 · HackTricks L485-539
│
└─ outer request scanned but sub-documents are not
      -> document-embedded payload: SVG, DOCX, XLSX, PPTX, EPUB
         PATT L475-644 · HackTricks L310-350
```

Per-host results record into the existing `recon/waf.py` profile
(`waf_profiles(host PRIMARY KEY)`, outcomes `allowed|stripped|blocked|modified|reset`,
locations `query|json|form|multipart|header|path`), extended with XML-specific
elements: `DOCTYPE`, `ENTITY`, `SYSTEM`, `PUBLIC`, `%`, `xi:include`, declared
encoding.

**Gap in every source: a blocked `SYSTEM` keyword.** No source documents a `PUBLIC`
identifier alternative. Worth probing and recording as original work.

---

## 7. Route survival

Reasons to care about any of this are offensive: each item below is something that
otherwise costs you the route, the finding, or both.

- **Marker per probe, or you have no finding.** A read primitive you cannot tie to
  your own request is not reportable — the first thing a triager asks for is the
  request that produced it. `recon/callbacks.py` `MARKER_RE` (16-96 chars) and
  `recon/fields.py` `mint_marker()` already mint them. Embed one in every probe
  document so the response is attributable and the evidence is findable in the
  ledger weeks later.
- **Rate control is throughput, not courtesy.** An account or IP cut off mid-route
  ends the route, and document-upload surfaces are the slowest to re-establish.
  `recon send` enforces scope, methods, rate and budget; external tooling does not,
  so its traffic needs the same ceilings applied by hand and counted against the
  same budget.
- **Own accounts, own uploaded documents.** Not restraint — control. A stored XXE
  payload in a DOCX or SVG persists until deleted and will be re-parsed on every
  view, by whoever views it. Keeping it in your own objects is what makes the
  trigger timing yours and the result readable.
- **DoS variants stay out of the ladder.** Billion Laugh, Parameters Laugh and the
  YAML variant (PATT L170-215, HackTricks L388-419) end your access to the target
  and are near-universally unpaid — mind-hunt itself calls the class "rarely pays".
  All three sources present them with no caution. Not a rung, not a channel, no
  case id.

---

## 8. Probe categories per rung

Category level only. The engine holds no payload literals — `csrf.py`, `ssrf.py` and
`fields.py` each contain zero — and concrete values come from the generator model via
`fields.packet()` → `fields.record_payload()`, with authorship recorded in
`payload_events`.

| Rung / step | Probe categories |
|---|---|
| `xxe-surface` | declared content type; content type swapped to each XML media type the server also parses; multipart with an XML part; document upload re-fetched and inspected |
| `xxe-parse` | well-formed vs malformed differential; unknown-element tolerance; declared-encoding variation |
| `xxe-entity` | internal general entity, benign value, referenced in a reflected node; nested internal entities; entity in attribute vs text position |
| channel: `in-band` | entity referenced where document content is echoed; base64-wrapped retrieval for binary-unsafe responses |
| channel: `error-local` | parameter-entity redefinition of an entity declared in an on-disk DTD; candidate DTD paths from OS fingerprint; verbosity probe to confirm errors carry content |
| channel: `error-external` | attacker-hosted DTD that redefines an entity so the value lands in an error |
| channel: `oob` | two-stage external DTD: parameter entity loads file, second parameter entity embeds it in a request to a controlled host; alternate protocol for multi-line content |
| channel: `blind` | external fetch with no recovery path — records the fetch, not the content |
| `xxe-read` | attacker-chosen path, varied per OS fingerprint; wrapper-encoded read where raw content breaks the document |
| `xxe-pivot` | internal host and port reachability through the fetch primitive; cloud metadata endpoints; protocol variation on the fetch |
| doc-upload variants | payload in `[Content_Types].xml`; payload in `word/document.xml`; SVG entity in a rendered image; XLSX sheet XML; re-zip and upload |

---

## 9. Module design — `recon/xxe.py`

Shape A (probe ladder), modelled on `recon/ssti.py` and `recon/csrf.py`.

```
xxe_sinks
  id, asset_id, origin, route, method, sink_kind, selector,
  discovery_basis, priority, sources, parser_hint, created, updated
  UNIQUE(asset_id, sink_kind, selector)

xxe_contexts
  id, sink_id, content_type, channel, account, role, workflow,
  basis, facets, detail, created, updated
  UNIQUE(sink_id, content_type, channel, account, role, workflow)

xxe_case_events
  id, context_id, case_id, variant, state, attempt_kind,
  marker, response_ref, control_response_ref,
  facets, counts, artifacts, tool_refs, note, created
  INDEX (context_id, case_id, id)
```

Vocabularies:

```
CASES         xxe-surface | xxe-parse | xxe-entity | xxe-read | xxe-pivot
CHANNELS      in-band | error-local | error-external | oob | blind
SINK_KINDS    declared-xml | soap | content-type-flip | doc-upload | saml |
              feed | xmlrpc | pdf-embedded | xslt | jar-archive
STATES        attempted | observed | negative | blocked | inconclusive | n-a
ATTEMPT_KINDS native | browser | replay | review
FACETS        doctype | entity | system | encoding | content-type | wrapper
ARTIFACT_ROLES request | response | error-body | probe-document | trace
```

Per-host parser profile, mirroring `recon/waf.py`:

```
xxe_profiles(host PRIMARY KEY)
  parser_family, language, entity_posture, parameter_entity_posture,
  doctype_filtered, system_filtered, error_verbosity,
  local_dtd_found, local_dtd_path, encodings_accepted,
  content_types_parsed, updated
```

Learned once per host. HackTricks gives nothing on .NET, Python/lxml, libxml2
versions, Node or Go, and never states which stacks are default-secure — so the
profile starts empty and fills by observation, not from a copied table.

Grant schema for the three egress channels, copying the pattern at
`recon/fields.py:719-721`:

```python
hosts = (config.get("callback_hosts") if isinstance(config, dict) else None) \
    or self.ctx.campaign.raw.get("ssrf", {}).get("callback_hosts", [])
require_callback_url(url, hosts, "xxe.callback_hosts", marker)
```

`recon/campaign.py` gains an `xxe` block with `callback_hosts: []`.
`require_callback_url` already takes the config name as a parameter, so the error
message stays class-accurate. `in-band` and `error-local` need no grant.

CLI surface:

```
recon xxe probes  <campaign>              inert control set per sink kind
recon xxe surface <campaign>              sink inventory with discovery basis
recon xxe plan    <campaign> [--sink N]   ranked sink x channel x case cards
recon xxe record  <campaign> --context N --case C --channel H --state S ...
recon xxe status  <campaign>              ladder per sink, channel coverage
recon xxe verify  <campaign> --event N    re-check a recorded pairing
```

---

## 10. Proof binding

Bind every rung to stored evidence through `recon/factcheck.py`, whose accepted
predicates are `status_is`, `header_present`, `header_equals` and
`body_contains_raw` (marker 1-1024 bytes). Free-form claims are rejected.

| Rung | Binding |
|---|---|
| `xxe-parse` | `status_is` or `body_contains_raw` on the malformed-document differential, against the well-formed control |
| `xxe-entity` | `body_contains_raw` on the substituted marker value |
| `xxe-read` | `body_contains_raw` on a distinctive string from the target file |
| `xxe-pivot` | `body_contains_raw` on a distinctive string from the internal response |

Note: the predicate set has **no negation**. Proving substitution rather than echo
requires a separately recorded control response showing the literal form did *not*
come back — which is how the engine records negative controls anyway. Each event
carries both `response_ref` and `control_response_ref`.

Per ARTEX doctrine: measured impact as a number with its denominator, and the proof
basis stated as `executed-live`, `executed-lab` or `static-analysis-unexecuted`.

---

## 11. Chains

All target classes exist in `score.py`'s 20, so these resolve:

```
file-upload  -> xxe            SVG / DOCX / XLSX / PPTX re-parsed server-side
saml         -> xxe            SAML response parsing  (class saml, hunt-saml exist)
xxe          -> file-read      the read primitive
xxe          -> ssrf           the fetch primitive; also the mind-hunt L112 fallback
                               when the DTD is fetched but file:// is refused
```

No `rce` class exists, so HackTricks' XMLDecoder (L783-849) and command-wrapper
(L611) paths have no chain target. Record them as out-of-ladder notes on the sink
rather than writing an edge to a class that is not there.

`xxe` is currently seeded but appears in no chain, so these four rows close a dead
end.

---

## 12. Wiring — must land together

`tests/test_recon_skills.py:376-381` requires the skill file to exist, to appear in
`catalog.HUNT_SKILLS`, and for the mapped-skill set to equal the catalog set.

```
.claude/skills/hunt-xxe/SKILL.md
.claude/skills/hunt-xxe/references/{surfaces.md,channels.md,bypass-tree.md,sources.md}
.claude/skills/hunt-xxe/evals/{channel-is-not-rung,inert-first,surface-closure}/
recon/xxe.py
recon/catalog.py       HUNT_SKILLS entry
recon/skillmap.py      "xxe": ("hunt-xxe",)
recon/campaign.py      xxe.callback_hosts block
recon/findings.py      four chain rows
recon/waf.py           XML element vocabulary
recon/cli.py           xxe verb group + help line
tests/test_recon_xxe.py
AGENTS.md              xxe bullet, matching the csrf and ssti bullets
Handover.md            xxe.py row in the module table
```

Gate: `PYTHONPATH=. .venv/bin/python -c "import unittest; ..."` discover over
`tests`, green at 377+.

---

## 13. Evals

Matching the `hunt-csrf/evals/` layout — `case.yaml` plus `graders/*.md`.

**`channel-is-not-rung`** — an external DTD fetch recorded as `xxe-read` must fail.
The distinction mind-hunt states as a pitfall (L112) and HackTricks never ranks.

**`rung-evidence-complete`** — a claimed `xxe-read` whose lower rungs are neither
separately observed **nor** implied by the same response must fail. Preserves proof
integrity without constraining attack order: a direct read that lands proves
`xxe-parse` and `xxe-entity` in one response, and the grader accepts that.

**`route-not-abandoned`** — a sink marked `blocked` after a single failed attempt,
with no failure classification recorded (§5 step 3) and no channel switch attempted,
must fail. A filtered payload is not an impassable route.

**`surface-closure`** — a sink inventory claiming completeness while
`content-type-flip` was never attempted on JSON endpoints must fail. That surface is
invisible to `score.py` and requires the ARTEX discovery action.

---

## 14. Pipeline

```
LOCAL="ollama/hf.co/huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF:latest"   # CONTEXT 131072
FB="opencode/deepseek-v4.1-flash-free"
MERGE="anthropic/claude-opus-5-5"
DRAFT="codex exec"                                                          # codex-cli 0.167.0
```

meridian: `MERIDIAN_SESSION_TURN_MAX_HOLD_MS=1800000`,
`MERIDIAN_UPSTREAM_IDLE_MS=300000`.
OpenCode provider: `timeout 1860000`, `chunkTimeout 330000`,
`headerTimeout 120000`.

| Stage | Runner | Fallback |
|---|---|---|
| 0 — gap list, corpus stats | none | — |
| 1 — source pack, anchored excerpts with `path+lines+sha256` | none | — |
| 2 — draft to Shape A | `codex exec` | `$FB` |
| 3 — adversarial review, cited JSON | `$LOCAL` | `$FB` |
| 4 — citation validation, dedupe, rank, top 3 | none | — |
| 5 — merge + wiring | `$MERGE` | `codex exec` |
| 6 — gate: test suite | none | — |

Stages 0, 1, 4 and 6 never fall back because no model runs them.

```bash
C=xxe
D=skills-build/$C
run() {
  opencode run --model "$1" --archived --auto --format json -f "$3" > "$2" \
  || opencode run --model "$FB" --archived --auto --format json -f "$3" > "$2"
}
```

`skills-build/` gitignored — packs carry verbatim third-party excerpts and the repo
is public MIT.

### Pack contents for stage 1

```
PortSwigger      /web-security/xxe, /web-security/xxe/blind         (fetched, cited)
PayloadsAllThe~  XXE Injection/README.md L50-77, L148-156, L218-339,
                 L340-474, L475-644
HackTricks       L81-94, L166-308, L439-539
mind-hunt        hunt-xxe/SKILL.md L1-121
ARTEX            skills/api-security/SKILL.md:77
                 agent/promptcatalog.go L42-82
BugVault         .claude/skills/hunt-ssti/SKILL.md     (house template, Shape A)
                 recon/ssti.py                         (table + vocabulary shape)
                 recon/waf.py L32-64                   (profile + outcome shape)
                 recon/fields.py L719-721              (grant fallback pattern)
                 recon/factcheck.py L19-22             (predicate contract)
                 integration contract: catalog / skillmap / campaign / findings / cli
```

~40 KB ≈ 10,000 tokens ≈ **3.5 min of prefill** before the first byte.

**Size packs by prefill time, not by context.** Prefill runs at ~49 tok/s and Ollama
sends no response headers until generation starts — a measured 12,500-token prompt
took 254 s of prompt processing. Budget `prompt_tokens / 49` seconds.

| Pack | Tokens | Prefill |
|---|---|---|
| 10 KB | ~2,500 | ~50 s |
| 25 KB | ~6,000 | ~2 min |
| 40 KB | ~10,000 | ~3.5 min |
| 50 KB | ~12,500 | ~4.2 min |

Mitigations: keep a **stable prefix** so the llama.cpp prompt cache (8192 MiB) can
reuse it — house template and integration contract first, source excerpts last;
**split stage 3 per axis** into ~10 KB calls; **route large packs to `$FB`**, which
has no local prefill cost.

Configured: `providers.ollama.settings.headerTimeout` 1,800,000 ms (30 min, ≈88,000
prompt tokens), `timeout` 3,600,000, `chunkTimeout` 300,000, and
`OLLAMA_KEEP_ALIVE=4h` to hold the model and prompt cache between turns.

### Stage 3 review contract

Four questions, each answer requiring a citation resolvable inside the pack:

1. Which XML-consuming surfaces does the draft miss?
2. Where does the draft stop short of a rung or channel the sources document?
3. Which filter paths are uncovered — blocked `DOCTYPE`, blocked `SYSTEM`, encoding
   gates, content-type gates, sub-document scanning gaps?
4. Where is the draft's proof bar higher than the engagement requires, leaving
   demonstrable impact unproven?

```json
{"axis":"...","claim":"...","source_file":"...","line_start":0,"line_end":0,"why_missing":"..."}
```

Axes: surface discovery · detection ladder · channel selection · filter bypass ·
parser variation · proof binding · chain targets · attribution.

Stage 4 drops any item whose citation does not resolve in the pack, then ranks by
emptiest axis and keeps three. The script ranks; the model does not.

### Artifacts

```
skills-build/xxe/
  pack.md             bounded excerpts + provenance     (script)
  draft.codex.md      Shape A draft                      (codex)
  review.local.json   cited suggestions                  (qwen)
  review.local.md     same + ACCEPT/REJECT per item
  MANIFEST.json       model, prompt hash, pack sha256 per stage
```

---

## 15. Build order

1. `recon/xxe.py` — schema and vocabularies, then the ledger class, then CLI
   registration, then tests. **Four separate writes**, not one.
2. `recon/waf.py` XML element vocabulary — small, standalone.
3. Stage 1-2: pack and draft. Offline, no target contact.
4. Stage 3-4: local review, citation validation.
5. Stage 5: merge the skill, land all of §12 in one commit, gate on tests.
6. First live exercise: **`in-band` and `error-local` channels only.** Zero egress,
   no callback host, no grant needed.
7. Egress channels (`error-external`, `oob`, `blind`) once a campaign exists with
   `xxe.callback_hosts` populated.

Steps 1-5 touch no target.

---

## Sources

- https://portswigger.net/web-security/xxe
- https://portswigger.net/web-security/xxe/blind
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md
- https://github.com/b4rdia/HackTricks/blob/master/pentesting-web/xxe-xee-xml-external-entity.md
- https://github.com/BaaRai/ARTEX
- https://github.com/vxcontrol/pentagi
- https://github.com/0xN0RMXL/BugBountySkills
- https://www.yeswehack.com/learn-bug-bounty/xml-external-entity-guide-xxe
- mind-hunt (local, MIT, © 2026 MindflareX) — `skills/hunt-xxe/SKILL.md`
