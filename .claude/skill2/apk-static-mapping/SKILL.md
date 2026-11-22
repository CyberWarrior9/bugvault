---
name: apk-static-mapping
description: Map mobile attack surface from authorized APKs via external REA/JADX static analysis — decompiled endpoints, pinned old API versions, embedded secrets — recorded as untrusted leads, never as confirmed vulnerabilities.
---

# APK static mapping (external REA workflow)

Read scope-policy first. This phase uses an **external tool** ([REA](https://github.com/morluto/rea), MIT; run via `npx rea-agents` or `npm install --global rea-agents`) — it is not a BugVault handler and has no import adapter yet. Only analyze apps you are authorized to examine: your own build, an app on your own device/emulator, or a program whose written rules cover mobile testing.

Mobile apps are L3 deep-untested surface (plan4 §2): they pin **old API versions** (`/api/v1/` beside `/api/v3/`), reference **unlinked internal endpoints**, and sometimes ship **secrets** (API keys, endpoint allowlists, feature flags). Nobody tests this surface because web-only hunters never see it.

## Workflow

1. Obtain the APK legitimately (your device via adb pull, or an authorized artifact). Do not sideload from untrusted mirrors.
2. Static analysis (offline, no target contact):
   `rea analyze-android-application /absolute/path/to/app.apk --json`
   Requires headless JADX + a full JDK (REA orchestrates them). Also useful:
   `rea inspect_apk_signature` (v1/v2/v3 signers, certificate fingerprints, key rotation)
   and Apktool resource decoding for string tables and the decoded manifest.
3. From the decompiled evidence, extract: endpoint paths and base URLs, API versions,
   auth/token handling, certificate pinning configuration, embedded keys/tokens,
   deep-link/intent handlers, debug/test flags, backend feature flags.
4. Record what applies to in-scope hosts as leads:
   `python3 -m recon finding add <campaign> --title "..." --class <class> --url <url>`
   Link mobile-surface leads into chains (`finding link ... pivots-to ...`).
5. Test extracted endpoints only through the scoped client under current mode.
   A mobile-only endpoint reachable unauthenticated goes to the top of the queue.

## Boundaries

- REA runs locally and does not upload the app; its results carry evidence and
  limitations — treat both as untrusted tool output, exactly like Katana imports.
- Decompiled references are static evidence, not proof an endpoint is live or behaves
  as the code suggests. Verify through the scoped client before claiming anything.
- An embedded key alone is a **half finding**: reportable only after demonstrating it
  unlocks data or actions a normal visitor cannot touch (reportability gate Q3).
- REA's runtime/device capture (adb) runs with **your user permissions outside the
  scoped egress client** — same class as manual tools. Use an owned emulator, capture
  traffic to HAR, and import offline (`import-har`). Do not let a target app's traffic
  run unsandboxed before OS-level egress isolation exists.
- `npx` fetches from npm: pin the version, review what `setup` changes (it edits agent
  configs, with backups), and acquire from the official repo/npm package only.

Output: endpoint families and versions, secrets, deep-link handlers, pinning config —
all labelled as imported/untrusted leads feeding the coverage matrix. Implementation:
external `rea` CLI; recording via `recon/findings.py`. See `docs/rea-analysis.md`.
