# REA analysis — reverse engineering in the hunting pipeline

> Source: [morluto/rea](https://github.com/morluto/rea) ("Reverse Engineer Anything"),
> MIT-licensed, npm package `rea-agents`, 452k stars. Analyzed 2026-11-11 from the
> public README/docs. Not installed or integrated at analysis time.

## What it is

One MCP server + CLI giving agents reverse-engineering tools across binaries,
applications, and runtime behavior. Analysis runs **locally** (no app upload); results
include the evidence and limitations behind each conclusion — the same epistemic
discipline this repo enforces. Agents integrate via MCP (Claude Code, Codex, Cursor,
Gemini CLI…); the CLI emits JSON for deterministic pipelines. Node.js ≥22.23.4 /
≥24.22.1 / ≥26.12.1 required (this machine: v26.13.0 ✅).

Decompilation providers: JADX and Ghidra (free) cover our needs; IDA/Hopper/JEB are
optional and commercially licensed (REA grants no license — irrelevant to us).

## What we get, mapped to our gaps

| REA capability | BugVault gap it fills | Where |
|---|---|---|
| **Android APK analysis** (manifest, classes, decompiled methods, references via headless JADX) | **Mobile app backends as L3 deep-untested surface** — plan4 §2 lists "APK static analysis → hidden API endpoints (mobile apps pin old APIs)" with no tool assigned | New `apk-static-mapping` skill |
| APK signature inspection (v1–v3.1, cert fingerprints, key rotation) | Target provenance / repackaging checks in the apk-redteam-pipeline pack (plan4 §4) | Same skill |
| **Electron/JS app analysis** + `rea audit-release-exposure` | Desktop apps ship source maps, internal routes, IPC boundaries and sometimes secrets — extends our L2 static mapping beyond websites | Future adapter |
| Website observation, HAR/SAZ capture analysis | Complements our `har.py` (theirs adds source locations of exposed payloads) | Optional |
| .NET assemblies, native binaries, binary hardening, firmware (Binwalk/Unblob), Go/Rust metadata | Wide-but-later: thick-client and IoT programs | Backlog |
| **RL environments from recorded sessions** (record web-app session → API becomes agent tools → exportable env) | A **safe replay sandbox**: test chains against recorded behavior without touching the live target — directly serves the reportability gate's "finish the chain" rule | Future, high value |

## Where it slots in

Mobile is the immediate win. The hunt loop becomes:

```text
authorized APK → rea analyze-android-application --json (offline)
  → endpoints / old API versions / secrets / deep links / pinning config
  → recorded as untrusted leads (finding add) → coverage matrix
  → tested through the scoped client → evidence gates → report
```

## Trust model

- **Static analysis (APK/JS/.NET/binaries): offline, no target contact.** Identical
  trust class to our Katana/subfinder imports: untrusted tool output, labelled as
  imported, never promoted to confirmed. Clean fit.
- **Runtime/device capture (adb, process capture, browser observation): runs with the
  operator's permissions, outside our scoped egress client.** Same class as manual
  nmap/ffuf: fine operator-driven on owned emulators; **not** for autonomous use until
  OS-level egress isolation exists. Traffic must be captured to HAR and imported
  offline — never let a target app's traffic run unsandboxed.
- **RL environments:** replay of recordings, no live target — safe by construction,
  and the right place to practice chain completion.

## Agent invocation (the two paths)

1. **CLI + JSON export → deterministic pipeline** (preferred, matches our
   code-enforces/model-reasons split): operator or agent runs `rea analyze-* --json`,
   output lands as a pinned artifact, a future `recon import --format rea` adapter maps
   it to assets/endpoints/facts with provenance — same pattern as the five existing
   scanner adapters. **Blocked on:** pinning the export schema against a real REA run.
   No adapter is claimed until then.
2. **MCP registration → interactive agent investigation:** `npx rea-agents setup`
   registers the MCP server + workflow instructions with the agent harness (edits
   configs, keeps backups). This is what "an agent that invokes REA" looks like: the
   hunter-role agent calls REA tools during recon, gets evidence-backed findings back.
   Requires the model gateway/audit layer first (docs/model-routing.md §5) so REA
   calls are attributed like any other model-adjacent action.

## Risks

- **Supply chain:** npm package with 111k forks and a name-squatting warning in its
  own README. Pin the exact version, acquire from the official repo/npm only, review
  every `setup` diff. It edits agent configuration files.
- **Scope drift:** REA happily analyzes anything it's pointed at. Authorization comes
  from our scope.json and program rules, never from tool capability. The skill
  restates this.
- **Runtime capture** bypasses our egress controls (above).
- **Frida/verification configs** in the repo suggest dynamic instrumentation surface;
  treat as runtime-class until reviewed.

## Verdict

Use it, static-first. It is the missing tool for the L3 mobile-surface differentiator
and later for Electron exposure audits and replay-based chain practice. Integration
order: (1) manual skill workflow — done, `.claude/skills/apk-static-mapping/SKILL.md`;
(2) ingest adapter after pinning a real export schema; (3) MCP agent invocation after
the model gateway; (4) RL replay environments for chain completion drills.
