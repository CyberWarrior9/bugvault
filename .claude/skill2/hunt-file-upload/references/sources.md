# Sources and their limits (reviewed 2026-11-14)

Dates are source-file commits or document metadata, not proof that a technique
works today. Nothing below was copied into this skill: no payloads, shells,
artifacts or licensed prose. Each source contributed a question or a control, and
the workflow above is original BugVault text.

| Source | Pin | Used for | Limit |
|---|---|---|---|
| MindHunt `hunt-file-upload` | Operator-local snapshot, 56 lines, SHA-256 `fbf6057321153d8fc8228ee2555ec988e6b709b4c717a85bc2a7a199f2cdec61`; MIT notice © 2026 MindflareX | The stored-blob versus downstream-effect distinction | **Local-only, not publicly verifiable**: the `MindflareX/mind-hunt` repository returned 404 on 2026-11-14 and the snapshot has no Git history. Its prevalence rankings and chains are unverified; none of its payloads or wording is used. |
| PentAGI web-pentest prompt (MIT) | `vxcontrol/pentagi` commit `b90ea4711eb236c47b8a3fe926a2b78c89092502`, file touched 2026-03-26 | Inventory prompts: upload endpoints, URL import, document/XML surfaces, multipart fields | A short checklist; no processing/execution distinction, controls or budget. |
| ARTEX `php2shell` skill (AGPL-3.0) | `BaaRai/ARTEX` commit `750f4eb09164146fc2d2f59f23c71ecb9fdb59ac` (2026-10-21); license at `ae792126dcfbf7292899bea2bd6fcdc32f7083da` | Why a separately existing inclusion path matters; lab-first gating | A narrow, version-dependent lab chain. No AGPL code transplanted; its CVEs are not assumed to apply anywhere. |
| PayloadsAllTheThings, Upload Insecure Files (MIT) | `swisskyrepo/PayloadsAllTheThings` commit `e961fef231d8327bae83b563fab50aec2e6b77c0`, touched 2026-04-22 | Grouping into handler, filename, format, image, converter and archive consumer categories | A mixed-age anthology; not evidence any product processes a file. No artifact reuse. |
| HackTricks fork, file-upload page | `b4rdia/HackTricks` commit `9d61d9142c350c1f6188ffb3c5e6e34407cf8438`, README touched 2023-01-13 | Image transformation, archive and document outcome coverage | A frozen **2023** fork under CC BY-NC 4.0, historical only. Its PDF page retells a 2014 Adobe Reader case; no current server-side or browser behaviour is inferred. |
| OWASP WSTG BUSL-08/09, File Upload Cheat Sheet, ASVS v5.0.0 V5 | ASVS v5.0.0 released 2025-05-30 (5.1.1, 5.2.1–5.2.6, 5.3.1–5.3.3, 5.4.1–5.4.3); BUSL-09 substantive edit 2026-11-03 | The control baseline and requirement mapping | WSTG `/latest` is development guidance; v4.2 is the current versioned WSTG release. Principles only, not its high-risk examples. |
| Microsoft Learn, ASP.NET Core file uploads | `ms.date` 2026-10-03, metadata `updated_at` 2026-11-11 | Quarantine, background scan, generated names, no-execute storage | Vendor-specific illustration, not evidence about any target stack. |
| MITRE CWE-434 | Last updated 2026-10-28 | Consumer-required framing for execution | A weakness definition, not a test procedure. |
| tus resumable upload protocol | 1.0.0, 2016-03-25 | Whole-object versus per-part limits | A `PATCH` alone does not prove tus support. |
| FUEL / Fuxploider-NG paper | arXiv 2405.16619, submitted 2024-05-26 | A lab evaluation taxonomy to review | Not a completeness promise or a license to run a scanner; scenarios and license need review before deriving lab cases. |
| BugBountySkills | `0xN0RMXL/BugBountySkills` at `0accf5fdc71ec7f03273aebb99268a8609f8dfd4` | Considered as an alternative source | Has no `KNOWLEDGE_BASE/File_Upload` directory at that revision; not used for mechanism claims. |

## Corrections carried from the earlier draft

- The earlier draft's 377-test baseline was stale; its claim that BugVault had no
  upload→XSS chain hint was wrong (`recon/findings.py` has one).
- Its rule that a file must be served before processing can be tested was too
  absolute: a worker can process an ephemeral file without any public URL.
- Mapping code execution to access control would misclassify it; execution has
  its own `execution` route.
- Its ordered bypass tree, generated attack artifacts, EICAR-first preflight and
  "direct attempt first" sequence were not adopted.
