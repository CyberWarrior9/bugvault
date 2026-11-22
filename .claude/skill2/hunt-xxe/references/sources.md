# hunt-xxe — source provenance

Full build design, including the ledger module this skill does not yet have:
`plans/xxe.md`.

## Adapted material

| Source | Used | Excluded |
|---|---|---|
| mind-hunt `skills/hunt-xxe/SKILL.md`, SHA-256 `a1d5d685ab3fb4a8c7060e98dd7eb0c1c03d62918a8871d773af626af578fc2e` (MIT, © 2026 MindflareX) | the surface list ("Where XXE Still Lives"), the severity pitfalls that separate a fetched DTD from a file read, and the ordered test recipe | its curl recipes (this engine routes through `recon send` and the dedicated browser); its `security-arsenal` cross-reference (that skill is not imported); its credential-harvest severity advice |

## Referenced, not vendored

Read these directly rather than copying them in; they are the correctness baseline
when sources disagree.

- **PortSwigger Web Security Academy** — `/web-security/xxe` and
  `/web-security/xxe/blind`. Maintained, with labs. States the constraint that makes
  the blind design necessary (parameter entities can only be referenced inside the
  DTD) and names concrete local-DTD paths including the Windows one.
- **PayloadsAllTheThings**, `XXE Injection/` — 688 lines plus `Files/` and
  `Intruders/`. The richest file-format inventory of any source (SVG, SOAP, DOCX,
  XLSX, DTD) and a dedicated JSON-endpoint section.
- **HackTricks**, `pentesting-web/xxe-xee-xml-external-entity.md` — 876 lines. The
  only source that teaches the blind and error-based mechanism as a *model* rather
  than a payload list, including the egress-blocked local-DTD path and the spec
  behaviour that permits it. Carries no proof discipline: pair it with this skill's
  limits section.
- **ARTEX**, `skills/api-security/SKILL.md:77` — content-type tampering as a
  numbered discovery action, which is where the `content-type-flip` sink comes from.
  `agent/promptcatalog.go:42-82` for the proof doctrine: drive a route through, a
  filtered payload does not kill it, measured impact with a denominator.

## Assessed and contributing nothing

- **PentAGI** — two matches, both test fixtures
  (`backend/cmd/ftester/mocks/tools.go`, `backend/pkg/tools/args_test.go`). XXE does
  not appear in its web-pentest prompt.
- **BugBountySkills**, `KNOWLEDGE_BASE/XXE/` — 351 lines across `payloads.md`,
  `hunting-methodology.md` and `bypasses.md` containing **zero** occurrences of
  `DOCTYPE`, `!ENTITY`, `SYSTEM "` or `XInclude`. A generated shell; its metadata
  claims 14 reports and a `$0` average. Ten folders from that repo have been read
  directly, nine were shells and one marginal — treat its report indexes as data and
  its prose as absent.

## Corpus position

From `vault/_data/reports-merged.csv`: 38 reports, 45% bounty rate against a 43%
corpus average, $900 median, $6,000 maximum, 8 priced rows. Rare but above-median
yield. Known ceilings outside the sample: Twitter #248668 at $10,080, QIWI #99279 at
$3,137. Four XXE dossiers sit in `vault/35-Report-Studies/`.
