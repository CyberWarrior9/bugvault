#!/usr/bin/env python3
"""Enrich the report index from an h1-corpus SQLite build, without rewriting it.

Why a sidecar instead of new columns in `reports-merged.csv`:

  * That file's sha256 is recorded in `report-import-manifest.json`, and
    `import_report_index.py` rebuilds it from base + registered sources. Columns
    added out of band would be silently dropped on its next run.
  * This enrichment is additive and reversible: delete the sidecar and nothing
    about the existing index changes.

What this corpus actually adds, measured against the current index:

  * 12,428 of its 12,447 report ids are ALREADY in the vault. It is not a new
    index; it is a body/payload/classification layer over the one we have.
  * 9,726 rows gain a report body (the vault records `body_chars` but holds no
    text, and the manifest states `full_reports_fetched = False`).
  * 1,876 rows currently `unclassified` gain a real class.
  * 1,959 rows gain CVE references.

The existing `class` column is never touched. The corpus label is carried in
`h1corpus_primary_class` plus a `h1corpus_crosswalk_class` mapped into the vault's
own taxonomy, so the two are comparable without either overwriting the other.
Agreement on comparable rows is 82%; the disagreements are mostly the vault's
`unclassified` rows gaining a label, plus two genuine taxonomy differences
(`Access Control & IDOR` vs the vault's more specific `privilege-escalation`, and
`File, Path & Upload` vs `file-read`).

Bodies and payloads are NOT copied into the vault. They stay in the SQLite, which
is referenced by path and sha256; it is gitignored because it is 118 MB against an
8.5 MB .git. `reports_fts` gives full-text search over 68.1 MB of bodies.

Usage:
    python3 scripts/import_h1_corpus.py [--corpus PATH] [--check]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parent.parent
DEFAULT_CORPUS = REPO / "vault/_data/corpora/h1-corpus.sqlite3"
MERGED = REPO / "vault/_data/reports-merged.csv"
SIDECAR = REPO / "vault/_data/h1corpus-enrichment.csv"
QUARANTINE = REPO / "vault/_data/h1corpus-quarantine.jsonl"
MANIFEST = REPO / "vault/_data/report-import-manifest.json"
CROSSWALK_DOC = REPO / "vault/90-Meta/h1corpus-crosswalk.md"

FIELDS = ["id", "h1corpus_primary_class", "h1corpus_crosswalk_class", "h1corpus_classes",
          "h1corpus_class_count", "h1corpus_cves", "h1corpus_severity",
          "h1corpus_body_available", "h1corpus_body_sha256", "h1corpus_payload_count",
          "h1corpus_classification_source", "h1corpus_classification_confidence",
          "h1corpus_year", "h1corpus_url"]

# h1-corpus's 32 attack classes -> the vault index taxonomy (reports-merged.csv `class`).
# A value of "" means the corpus class has no vault equivalent: it is carried verbatim
# in h1corpus_primary_class and left unmapped rather than forced into a near-miss.
CROSSWALK: Dict[str, str] = {
    "Cross-Site Scripting": "xss",
    "Information Disclosure & Privacy": "info-disclosure",
    "Access Control & IDOR": "idor-bola",
    "Authentication, Sessions & MFA": "auth-bypass",
    "Business Logic & Abuse": "business-logic",
    "Memory Safety & Native Code": "memory-safety",
    "Other / Unclassified": "unclassified",
    "Command, Code & Template Injection": "rce",
    "Denial of Service & Resource Exhaustion": "dos",
    "Cross-Site Request Forgery": "csrf",
    "Cryptography & Transport Security": "crypto",
    "File, Path & Upload": "file-upload",
    "Open Redirect & URL Handling": "open-redirect",
    "Server-Side Request Forgery": "ssrf",
    "SQL & Data-Layer Injection": "sqli",
    "HTTP Desync & Request Smuggling": "http-smuggling",
    "Email, Header & Protocol Injection": "header-injection",
    "XML & XXE": "xxe",
    # --- no vault-index equivalent; deliberately unmapped
    "Configuration & Hardening": "",
    "Clickjacking & UI Redress": "",
    "Deserialization & Object Injection": "",
    "Social Engineering & Spoofing": "",
    "Race Conditions & Concurrency": "",
    "Prototype Pollution": "",
    "DNS & Subdomain Takeover": "",
    "CORS & Cross-Origin Policy": "",
    "Cache Poisoning & Web Cache": "",
    "Mobile & Client Applications": "",
    "API, GraphQL & WebSocket": "",
    "OAuth, SSO & Federation": "",
    "AI & LLM Security": "",
    "Supply Chain & Dependencies": "",
}

# Corpus classes that must never drive engine coverage, with the reason. They stay in
# the KB as disclosed history: the vault indexes what was reported, the engine hunts a
# narrower surface, and conflating the two would seed classes we do not test.
OUT_OF_ENGINE_SCOPE = {
    "Denial of Service & Resource Exhaustion": "DoS is excluded from every hunt plan",
    "Memory Safety & Native Code": "native/binary, not a web surface the engine maps",
    "Social Engineering & Spoofing": "no technical surface to seed",
    "AI & LLM Security": "no class or skill exists",
    "Supply Chain & Dependencies": "no class or skill exists",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def vault_ids() -> Dict[str, str]:
    out: Dict[str, str] = {}
    with io.open(MERGED, encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            rid = (row.get("id") or "").strip()
            if rid:
                out[rid] = (row.get("class") or "").strip()
    return out


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ap.add_argument("--check", action="store_true", help="report only; write nothing")
    args = ap.parse_args(argv)

    corpus = Path(args.corpus)
    if not corpus.is_file():
        print(f"corpus not found: {corpus}", file=sys.stderr)
        return 2
    if not MERGED.is_file():
        print(f"report index not found: {MERGED}", file=sys.stderr)
        return 2

    known = vault_ids()
    con = sqlite3.connect(f"file:{corpus}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row

    payload_counts = {str(r["report_id"]): r["n"] for r in con.execute(
        "SELECT report_id, COUNT(*) AS n FROM payloads WHERE report_id IS NOT NULL "
        "GROUP BY report_id")}
    meta = {r["key"]: r["value"] for r in con.execute("SELECT key, value FROM metadata")}

    rows: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []
    stats = {"corpus_reports": 0, "matched": 0, "unmatched": 0, "unmapped_class": 0,
             "class_agrees": 0, "class_differs": 0, "rescued_unclassified": 0,
             "gains_body": 0, "gains_cves": 0, "out_of_engine_scope": 0}

    for rec in con.execute("SELECT * FROM reports"):
        stats["corpus_reports"] += 1
        rid = str(rec["id"])
        existing = known.get(rid)
        if existing is None:
            # Not in the index. Recorded, never invented: the index is the authority on
            # which reports exist, and this importer only enriches.
            quarantined.append({"id": rid, "url": rec["url"],
                                "primary_class": rec["primary_class"],
                                "reason": "report id not present in reports-merged.csv"})
            stats["unmatched"] += 1
            continue
        stats["matched"] += 1

        primary = rec["primary_class"] or ""
        mapped = CROSSWALK.get(primary, "")
        if primary and not mapped:
            stats["unmapped_class"] += 1
        if primary in OUT_OF_ENGINE_SCOPE:
            stats["out_of_engine_scope"] += 1
        if mapped and existing:
            if mapped == existing:
                stats["class_agrees"] += 1
            else:
                stats["class_differs"] += 1
        if existing in ("unclassified", "") and primary and primary != "Other / Unclassified":
            stats["rescued_unclassified"] += 1

        try:
            classes = json.loads(rec["classes_json"] or "[]")
        except ValueError:
            classes = []
        try:
            cves = json.loads(rec["cves_json"] or "[]")
        except ValueError:
            cves = []
        if rec["body_available"]:
            stats["gains_body"] += 1
        if cves:
            stats["gains_cves"] += 1

        rows.append({
            "id": rid,
            "h1corpus_primary_class": primary,
            "h1corpus_crosswalk_class": mapped,
            "h1corpus_classes": "|".join(str(c) for c in classes if c),
            "h1corpus_class_count": len(classes),
            "h1corpus_cves": "|".join(str(c) for c in cves if c),
            "h1corpus_severity": rec["severity"] or "",
            "h1corpus_body_available": 1 if rec["body_available"] else 0,
            "h1corpus_body_sha256": rec["body_sha256"] or "",
            "h1corpus_payload_count": payload_counts.get(rid, 0),
            "h1corpus_classification_source": rec["classification_source"] or "",
            "h1corpus_classification_confidence": rec["classification_confidence"] or "",
            "h1corpus_year": rec["year"] or "",
            "h1corpus_url": rec["url"] or "",
        })

    rows.sort(key=lambda r: int(r["id"]))

    print(f"  corpus reports            : {stats['corpus_reports']}")
    print(f"  matched into the index    : {stats['matched']}")
    print(f"  quarantined (not indexed) : {stats['unmatched']}")
    print(f"  class agrees / differs    : {stats['class_agrees']} / {stats['class_differs']}")
    print(f"  unclassified -> classified: {stats['rescued_unclassified']}")
    print(f"  rows gaining a body       : {stats['gains_body']}")
    print(f"  rows gaining CVE refs     : {stats['gains_cves']}")
    print(f"  corpus class unmapped     : {stats['unmapped_class']}")
    print(f"  out-of-engine-scope rows  : {stats['out_of_engine_scope']}")

    if args.check:
        print("  --check: nothing written")
        return 0

    SIDECAR.parent.mkdir(parents=True, exist_ok=True)
    with io.open(SIDECAR, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    with io.open(QUARANTINE, "w", encoding="utf-8") as fh:
        for q in quarantined:
            fh.write(json.dumps(q, sort_keys=True) + "\n")

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.is_file() else {}
    manifest.setdefault("enrichments", {})["h1corpus"] = {
        "importer": "scripts/import_h1_corpus.py",
        "corpus_path": str(corpus.relative_to(REPO)) if corpus.is_relative_to(REPO) else str(corpus),
        "corpus_sha256": sha256_file(corpus),
        "corpus_built_at": json.loads(meta.get("built_at", '""')) if meta.get("built_at", "").startswith('"') else meta.get("built_at", ""),
        "corpus_schema_version": meta.get("schema_version", ""),
        "sidecar": {"path": "_data/h1corpus-enrichment.csv", "sha256": sha256_file(SIDECAR),
                    "rows": len(rows)},
        "quarantine": {"path": "_data/h1corpus-quarantine.jsonl", "records": len(quarantined)},
        "counts": stats,
        "policy": {
            "existing_class": "never overwritten; corpus label kept in h1corpus_* columns",
            "bodies": "not copied into the vault; stay in the SQLite, searchable via reports_fts",
            "payloads": "not copied; counted per report in h1corpus_payload_count",
            "unmapped_classes": "carried verbatim, never forced into a near-miss vault class",
            "out_of_engine_scope": OUT_OF_ENGINE_SCOPE,
            "reproduction_status": "not-reproduced; a disclosed report is precedent, not evidence",
        },
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\n  wrote {SIDECAR.relative_to(REPO)} ({len(rows)} rows)")
    print(f"  wrote {QUARANTINE.relative_to(REPO)} ({len(quarantined)} records)")
    print(f"  updated {MANIFEST.relative_to(REPO)} -> enrichments.h1corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
