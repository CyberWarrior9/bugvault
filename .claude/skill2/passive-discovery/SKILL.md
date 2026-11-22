---
name: passive-discovery
description: Collect authorized BugVault certificate and archived-URL inventory, or ingest existing subfinder and BBOT discovery artifacts without scanning targets.
---

# Passive discovery

Read the scope-policy guide first. Use `policy.mode=passive` for zero HTTP requests to the target; crt.sh and Wayback are third-party disclosures and may still be restricted by program rules.

Run `python3 -m recon run <campaign> --max-jobs 100` only after authorization review. For existing artifacts use `python3 -m recon import <campaign> <file> --format subfinder` or `--format bbot`; imports themselves use no network.

Retain source attribution and import hashes. Classify archive references as historical, not current liveness. Out-of-scope discoveries belong in intel, never new authorization. Imported BBOT finding/vulnerability events are unsupported, not confirmed findings.

Output host and archive-reference inventory with provenance and skipped jobs. Implementation: `recon/sources.py`, `recon/ingest.py`.
