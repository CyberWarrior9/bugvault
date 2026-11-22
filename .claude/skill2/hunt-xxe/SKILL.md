---
name: hunt-xxe
description: "Use for every BugVault xxe coverage row and whenever an in-scope surface parses XML: declared XML and SOAP endpoints, JSON endpoints that also accept XML after a content-type flip, document uploads that are zip-of-XML (DOCX/XLSX/PPTX/SVG/EPUB), SAML responses, RSS/Atom imports, XML-RPC and PDF-embedded XML. Separates what was established (rung) from how the evidence returned (channel); in-band and error-local channels prove file read with no outbound traffic and no callback grant."
license: "MIT; original BugVault workflow. Surface list and severity pitfalls adapted from mind-hunt (MIT, (c) 2026 MindflareX); see references/sources.md"
metadata:
  implementation: "recon/score.py:226 xxe seeding; recon/fields.py canary/trace for blind surfaces; recon/callbacks.py grant validation for egress channels; no dedicated ledger module"
  reviewed: "2026-11-19"
---

# Hunt: XML external entity

Two independent questions, and conflating them is the mistake this class invites:

- **Rung** — what was established. Surface → parse → entity → read → pivot.
- **Channel** — how the evidence came back. `in-band`, `error-local`,
  `error-external`, `oob`, `blind`.

A fetched external DTD with `file://` refused is **entity processing on the `blind`
channel**, not file read. That distinction is the single most common over-claim in
this class.

**`in-band` and `error-local` reach proven file read with zero outbound traffic** —
no callback receiver, no `xxe.callback_hosts` grant, nothing leaving the host. Start
there; the egress channels are an optional extra, not a prerequisite.

The unit of work is **one sink × one channel**. A negative on one channel does not
close another.

## Workflow

1. Read `scope-policy` and the campaign's written rules. Use supplied test accounts
   and the dedicated browser through Burp, or a recorded campaign execution path.
2. Inventory sinks. `score.py:226` seeds `xxe` on `\.xml$|soap|wsdl|xmlrpc` paths and
   on any asset whose observed content types include `xml`. It **cannot** see the
   content-type-flip sink, because nothing advertises it — see below.
3. Attempt the read directly on the cheapest channel for that sink. Do not walk the
   rungs upward: a direct read that lands proves every rung beneath it in one
   response, and you record them from that response rather than re-probing.
4. If it fails, classify *why* (the channel table), switch channel, then switch sink
   kind. A filtered payload does not close a sink.
5. Record with `python3 -m recon cov <campaign> <asset_id> xxe <status>` and
   `python3 -m recon finding add <campaign> --class xxe`. For blind surfaces, mint a
   marker with `recon fields canary` and locate it with `recon fields trace`.

## Sinks

| `sink_kind` | Where |
|---|---|
| `declared-xml` | endpoints advertising `application/xml` or `text/xml` |
| `soap` | legacy enterprise APIs, `/soapserver/`, WSDL-described operations |
| `content-type-flip` | **a JSON endpoint that also parses XML** — invisible to recon seeding, found by flipping the declared content type on endpoints that advertise JSON only |
| `doc-upload` | DOCX, XLSX, PPTX, SVG, EPUB — zip-of-XML; the payload goes in `[Content_Types].xml` or `word/document.xml`, then re-zip |
| `saml` | SAML response parsing; class `saml` and `hunt-saml` also apply |
| `feed` | RSS, Atom, OPML, sitemap import |
| `xmlrpc` | XML-RPC endpoints |
| `pdf-embedded` | PDF parsers handling embedded XML |
| `xslt` | XSLT transformation inputs |
| `jar-archive` | `jar:` protocol and Java archive handling |

`content-type-flip` is the highest-yield sink on a modern stack precisely because
nothing in the application advertises it. Flip the content type on JSON endpoints
that accept a body and see whether the parser engages.

Parser-default caution: modern Java and Python parsers ship with external entities
disabled. Prioritise SOAP, SAML, feed import and document upload over plain JSON
APIs — that ordering is where the disclosed cases are.

## Channels

| Channel | Egress | Grant | Mechanism |
|---|---|---|---|
| `in-band` | none | no | content reflected directly in the response |
| `error-local` | **none** | **no** | content embedded in a parser error, using a DTD already present on the target filesystem |
| `error-external` | yes | yes | the same, using an attacker-hosted DTD |
| `oob` | yes | yes | two-stage external DTD; content leaves in a request to a controlled host |
| `blind` | yes | yes | the fetch is observable; the content is not |

### Choosing a channel

```
does the document echo content back?          -> in-band
are parser errors verbose, and is a usable
  local DTD present on this platform?         -> error-local      [no egress]
errors verbose but no local DTD located?      -> error-external
no reflection and no errors?                  -> oob
only the fetch is observable?                 -> blind  (this is not read)
```

`error-local` works by redefining, from the internal DTD, an entity declared in a
DTD already on the target. Candidate paths follow the platform signal from
`recon/fingerprint.py`; a wrong platform guess is a miss, not a negative.

The egress channels require `xxe.callback_hosts` in `scope.json`, copied from the
program's written rules, validated by `recon/callbacks.py`
(`require_callback_url`, falling back to `ssrf.callback_hosts`). Minted markers come
from `recon/callbacks.py mint_marker`.

## When a probe is refused

Classify the refusal before trying another payload — the control that refused you
tells you which path is guarded.

| Refusal | Next |
|---|---|
| DOCTYPE declaration rejected outright | XInclude: it needs no DOCTYPE, and it is also the path when you control only part of the document |
| DOCTYPE allowed, entity declaration matched | parameter-entity nesting; comment injection inside the declaration; whitespace and formatting variation |
| payload matched on byte content | re-encode the document: alternate declared encodings |
| `file://` refused but the external fetch succeeds | language wrappers; archive protocols. If nothing reads, this is entity processing on `blind` — pivot to class `ssrf`, do not record read |
| egress blocked entirely | `error-local` |
| content type restricted to JSON | the content-type flip |
| outer request scanned, sub-documents not | the document-embedded sinks: SVG, DOCX, XLSX, PPTX |

A blocked `SYSTEM` keyword has no documented alternative in any source consulted.
Probe it and record the result as original work.

## Chains

| Edge | Note |
|---|---|
| `file-upload` → `xxe` | SVG / DOCX / XLSX / PPTX re-parsed server-side |
| `saml` → `xxe` | SAML response parsing; `hunt-saml` also applies |
| `xxe` → `file-read` | the read primitive |
| `xxe` → `ssrf` | the fetch primitive, including the DTD-fetched-but-no-read fallback |

No `rce` class exists in the engine, so XMLDecoder-style and command-wrapper paths
have no chain target. Record them as notes on the sink rather than as an edge.

## Interpretation and limits

- **A callback alone is not file disclosure.** It proves the parser resolved an
  external entity. That is the `blind` or `oob` channel at the entity rung, and the
  read rung needs the content back.
- One benign, world-readable path demonstrates that an attacker-chosen path is read;
  that is what establishes arbitrary read. Argue severity from what the primitive
  *reaches*, not by harvesting credential files or environment data. The engine's
  reportability gate and the validator decide the rest.
- **Entity-expansion denial of service is out of scope** — billion-laughs,
  parameter-laughs and the YAML variant. Every consulted source presents them with
  no caution; AGENTS.md excludes them. Not a rung, not a channel, no case.
- A stored payload in an uploaded document persists and re-parses on every view.
  Use your own objects, record the landing path, and remove it when the program
  allows.
- Respect rate and budget limits; external DTD fetches are requests too, and they
  count.

See [references/sources.md](references/sources.md) for the source provenance and
`plans/xxe.md` for the full build design, including the ledger module this skill
does not yet have.
