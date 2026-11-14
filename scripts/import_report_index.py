#!/usr/bin/env python3
"""Merge pinned public report indexes with BugVault's original H1 index.

Only metadata is imported. No report pages, payloads, or upstream scripts run.
The original index and report dossiers are never modified.
"""
import argparse
import csv
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
import urllib.parse
import urllib.request


SOURCE = "reddelexc/hackerone-reports"
BASE_SOURCE = "Hacker0x01/hackerone_disclosed_reports"
DEFAULT_REVISION = "4c279ab93db2791adf4d6775d7539ee05b02cdb0"
CODEBYGK_SOURCE = "codebygk/hackerone-bug-bounty-reports"
CODEBYGK_REVISION = "cb5d63cd158c4601978fee9687d65385853019b5"
BUGBOUNTYSKILLS_SOURCE = "0xN0RMXL/BugBountySkills"
BUGBOUNTYSKILLS_REVISION = "e0414b47a7de0f5588adb9404de7c6975614f2c0"
SOURCE_CONFIGS = {
    SOURCE: {"slug": "reddelexc-hackerone-reports", "remote_path": "data.csv",
             "filename": "data.csv", "revision": DEFAULT_REVISION},
    CODEBYGK_SOURCE: {"slug": "codebygk-hackerone-bug-bounty-reports",
                     "remote_path": "data/reports.json", "filename": "reports.json",
                     "revision": CODEBYGK_REVISION},
    BUGBOUNTYSKILLS_SOURCE: {"slug": "bugbountyskills-subdomain-takeover",
                             "remote_path": "KNOWLEDGE_BASE/Subdomain_Takeover/reports-index.md",
                             "filename": "reports-index.md",
                             "revision": BUGBOUNTYSKILLS_REVISION},
}
SOURCE_ALIASES = {"reddelexc": SOURCE, "codebygk": CODEBYGK_SOURCE,
                  "takeover": BUGBOUNTYSKILLS_SOURCE}
MAX_SOURCE_BYTES = 50 * 1024 * 1024
SOURCE_FIELDS = ["program", "title", "link", "upvotes", "bounty", "vuln_type"]
BASE_FIELDS = [
    "id", "title", "url", "substate", "weakness", "class", "team",
    "has_bounty", "vote_count", "disclosed_at", "body_chars",
]
EXTRA_FIELDS = [
    "program_name", "source_title", "source_weakness", "source_vote_count",
    "source_bounty_amount", "source_bounty_status", "sources",
    "source_revision", "source_record", "knowledge_status",
    "reproduction_status", "body_availability", "study_note",
    "metadata_status",
    "codebygk_title", "codebygk_program_name", "codebygk_weakness",
    "codebygk_vote_count", "codebygk_bounty_amount", "codebygk_bounty_status",
    "codebygk_severity", "codebygk_state", "codebygk_asset_type",
    "codebygk_submitted_at", "codebygk_disclosed_at", "codebygk_revision", "codebygk_record",
    "bbtakeover_title", "bbtakeover_program_name", "bbtakeover_severity",
    "bbtakeover_claimed_class", "bbtakeover_revision", "bbtakeover_record",
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_url(revision, source=SOURCE):
    if source not in SOURCE_CONFIGS:
        raise ValueError(f"unsupported source: {source}")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("revision must be a full, lowercase 40-character Git commit SHA")
    return f"https://raw.githubusercontent.com/{source}/{revision}/{SOURCE_CONFIGS[source]['remote_path']}"


def report_id(link):
    link = link.strip()
    parsed = urllib.parse.urlsplit(link if "://" in link else "https://" + link)
    if parsed.scheme not in ("http", "https") or parsed.netloc.lower() != "hackerone.com":
        raise ValueError("not a canonical HackerOne report link")
    match = re.fullmatch(r"/reports/([1-9][0-9]*)/?", parsed.path)
    if not match:
        raise ValueError("invalid HackerOne report path")
    return match.group(1)


def quarantine_entry(record, line, fields, reason):
    return {"record": record, "line_end": line, "reason": reason, "fields": fields}


def parse_source(data):
    # Do not sniff the dialect: an early sample can incorrectly disable doubled
    # quote escaping and make valid titles appear to have extra columns.
    reader = csv.reader(io.StringIO(data.decode("utf-8-sig"), newline=""),
                        dialect="excel", strict=True)
    if next(reader, None) != SOURCE_FIELDS:
        raise ValueError("unexpected source CSV header")
    reports, quarantine = {}, []
    row_count = duplicate_count = 0
    for record, fields in enumerate(reader, 2):
        row_count += 1
        issue = None
        rid = None
        if len(fields) != len(SOURCE_FIELDS):
            issue = f"expected {len(SOURCE_FIELDS)} fields, got {len(fields)}"
            # Keep an unambiguous ID/link discoverable, but quarantine ALL other
            # metadata rather than guessing where a broken title or amount ends.
            candidates = set()
            for value in fields:
                try:
                    candidates.add(report_id(value))
                except ValueError:
                    pass
            if len(candidates) == 1:
                rid = candidates.pop()
        else:
            row = dict(zip(SOURCE_FIELDS, fields))
            try:
                rid = report_id(row["link"])
                if not re.fullmatch(r"[0-9]+", row["upvotes"]):
                    raise ValueError("upvotes must be a non-negative integer")
                amount = Decimal(row["bounty"])
                if not amount.is_finite() or amount < 0:
                    raise ValueError("bounty must be a finite, non-negative number")
            except (ValueError, InvalidOperation) as error:
                issue = str(error) or "invalid bounty amount"
        if issue:
            quarantine.append(quarantine_entry(record, reader.line_num, fields, issue))
            if rid is None:
                continue
            item = {
                "id": rid, "program_name": "", "title": "", "weakness": "",
                "votes": "", "bounty_amount": "", "bounty_status": "unknown",
                "metadata_status": "external-quarantined", "record": str(record),
            }
        else:
            item = {
                "id": rid, "program_name": row["program"], "title": row["title"],
                "weakness": row["vuln_type"], "votes": str(int(row["upvotes"])),
                "bounty_amount": format(amount, "f") if amount > 0 else "",
                "bounty_status": "reported-positive" if amount > 0 else "unknown-or-zero",
                "metadata_status": "parsed", "record": str(record),
            }
        if rid in reports:
            previous = {k: v for k, v in reports[rid].items() if k != "record"}
            current = {k: v for k, v in item.items() if k != "record"}
            if previous != current:
                raise ValueError(f"conflicting source records for report {rid}; import aborted")
            duplicate_count += 1
        else:
            reports[rid] = item
    return reports, quarantine, row_count, duplicate_count


def parse_codebygk_source(data):
    payload = json.loads(data.decode("utf-8-sig"))
    if not isinstance(payload, dict) or not isinstance(payload.get("reports"), list):
        raise ValueError("expected codebygk JSON object with a reports array")
    reports, quarantine = {}, []
    duplicates = 0
    text_fields = ["title", "program", "vulnerability_type", "severity", "state",
                   "asset_type", "submitted_at", "disclosed_at"]
    for record, row in enumerate(payload["reports"], 1):
        rid = None
        try:
            if not isinstance(row, dict) or not isinstance(row.get("url"), str):
                raise ValueError("report must be an object with a string URL")
            rid = report_id(row["url"])
            if any(row.get(key) is not None and not isinstance(row[key], str) for key in text_fields):
                raise ValueError("text metadata must be a string or null")
            votes = row.get("upvotes")
            if type(votes) is not int or votes < 0:
                raise ValueError("upvotes must be a non-negative integer")
            amount = Decimal(str(row.get("bounty")))
            if not amount.is_finite() or amount < 0:
                raise ValueError("bounty must be a finite, non-negative number")
        except (ValueError, InvalidOperation) as error:
            quarantine.append(quarantine_entry(record, None, row, str(error) or "invalid bounty"))
            if rid is None:
                continue
            item = {
                "id": rid, "program_name": "", "title": "", "weakness": "", "votes": "",
                "bounty_amount": "", "bounty_status": "unknown",
                "metadata_status": "external-quarantined", "record": str(record),
                **{key: "" for key in text_fields if key not in ("title", "program", "vulnerability_type")},
            }
        else:
            item = {
                "id": rid, "title": row.get("title") or "", "program_name": row.get("program") or "",
                "weakness": row.get("vulnerability_type") or "", "votes": str(votes),
                "bounty_amount": format(amount, "f") if amount > 0 else "",
                "bounty_status": "reported-positive" if amount > 0 else "unknown-or-zero",
                "metadata_status": "parsed", "record": str(record),
                **{key: row.get(key) or "" for key in text_fields
                   if key not in ("title", "program", "vulnerability_type")},
            }
        if rid in reports:
            previous = {key: value for key, value in reports[rid].items() if key != "record"}
            current = {key: value for key, value in item.items() if key != "record"}
            if previous != current:
                raise ValueError(f"conflicting source records for report {rid}; import aborted")
            duplicates += 1
        else:
            reports[rid] = item
    return reports, quarantine, len(payload["reports"]), duplicates


TAKEOVER_SEVERITIES = frozenset({"critical", "high", "medium", "low", "none", "informational"})
TAKEOVER_LINK = re.compile(r"^\[link\]\((https?://hackerone\.com/reports/[1-9][0-9]*/?)\)$")
TAKEOVER_FIELDS = ["ID", "Title", "Program", "Severity", "Bounty", "Sub-type", "Quality", "URL"]


def parse_bugbountyskills_source(data):
    """Parse the BugBountySkills Subdomain_Takeover reports-index markdown table.

    The upstream knowledge base is AI-generated (its own history documents filler
    removal); only the report table is trusted here, and only as attributed source
    claims. Severity and the takeover class label are source claims, never current
    validation decisions.
    """
    reports, quarantine = {}, []
    row_count = duplicate_count = 0
    header_seen = False
    for record, line in enumerate(data.decode("utf-8-sig").splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("|"):
            if header_seen:
                break
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if cells and cells[0].lower() == "id":
            if header_seen or cells != TAKEOVER_FIELDS:
                raise ValueError("unexpected takeover report table header")
            header_seen = True
            continue
        if not header_seen:
            continue
        if cells and all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
            if len(cells) != len(TAKEOVER_FIELDS) or not all(cells):
                raise ValueError("unexpected takeover report table separator")
            continue  # table separator
        row_count += 1
        issue = None
        rid = None
        if len(cells) != 8:
            issue = f"expected 8 table fields, got {len(cells)}"
        else:
            rid_cell, title, program, severity, _bounty, _subtype, _quality, link = cells
            match = TAKEOVER_LINK.match(link)
            try:
                if not match:
                    raise ValueError("table link must be a [link](hackerone.com/reports/<id>) cell")
                rid = report_id(match.group(1))
                if rid != rid_cell:
                    raise ValueError("table ID and link report ID disagree")
                if not title or not program:
                    raise ValueError("title and program must be non-empty")
                if severity.lower() not in TAKEOVER_SEVERITIES:
                    raise ValueError("severity must be a known source label")
            except ValueError as error:
                issue = str(error)
                rid = rid if rid and rid == rid_cell else None
        if issue:
            quarantine.append(quarantine_entry(record, record, cells, issue))
            if rid is None:
                continue
            item = {"title": "", "program_name": "", "severity": "",
                    "record": record, "metadata_status": "external-quarantined"}
        else:
            item = {"title": title, "program_name": program, "severity": severity.lower(),
                    "record": record, "metadata_status": "parsed"}
        if rid in reports:
            duplicate_count += 1
            previous = {k: v for k, v in reports[rid].items() if k != "record"}
            current = {k: v for k, v in item.items() if k != "record"}
            if previous != current:
                raise ValueError(f"conflicting duplicate rows for report {rid}")
            continue
        reports[rid] = item
    if not header_seen or not row_count:
        raise ValueError("expected a non-empty takeover report table")
    return reports, quarantine, row_count, duplicate_count


def read_base(data):
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True)
    if reader.fieldnames != BASE_FIELDS:
        raise ValueError("unexpected base CSV header; use the original _data/reports.csv")
    reports = {}
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise ValueError("malformed base CSV; original index was not modified")
        rid = row["id"]
        if not re.fullmatch(r"[1-9][0-9]*", rid) or report_id(row["url"]) != rid:
            raise ValueError("base report ID and canonical URL disagree")
        if rid in reports:
            raise ValueError(f"duplicate base report ID: {rid}")
        reports[rid] = row
    return reports


def merge_reports(base, incoming, vault, revision):
    # Reuse the base index's exact weakness-to-class crosswalk. Unknown or
    # ambiguous weaknesses remain unclassified; titles never establish a class.
    classes = {}
    for row in base.values():
        if row["weakness"]:
            classes.setdefault(row["weakness"], set()).add(row["class"])
    merged = []
    for rid in sorted(base.keys() | incoming.keys(), key=int):
        row = {name: "" for name in BASE_FIELDS + EXTRA_FIELDS}
        original, external = base.get(rid), incoming.get(rid)
        if original:
            row.update(original)
            row["sources"] = BASE_SOURCE
            row["body_availability"] = (
                "dataset-body-present" if int(original["body_chars"] or 0) > 0
                else "dataset-body-empty"
            )
        else:
            row.update({"id": rid, "url": f"https://hackerone.com/reports/{rid}",
                        "class": "unclassified", "body_availability": "not-fetched"})
        row.update({"knowledge_status": "source-indexed",
                    "reproduction_status": "not-reproduced", "metadata_status": "parsed"})
        note = Path("35-Report-Studies") / f"rs-{rid}.md"
        if (vault / note).is_file():
            row["study_note"] = note.as_posix()
        if external:
            row.update({
                "program_name": external["program_name"],
                "source_title": external["title"],
                "source_weakness": external["weakness"],
                "source_vote_count": external["votes"],
                "source_bounty_amount": external["bounty_amount"],
                "source_bounty_status": external["bounty_status"],
                "sources": ";".join(filter(None, [row["sources"], SOURCE])),
                "source_revision": revision, "source_record": external["record"],
                "metadata_status": external["metadata_status"],
            })
            if not original:
                candidates = classes.get(external["weakness"], set())
                row.update({
                    "title": external["title"], "weakness": external["weakness"],
                    "class": next(iter(candidates)) if len(candidates) == 1 else "unclassified",
                    "vote_count": external["votes"],
                    "has_bounty": "True" if external["bounty_amount"] else "",
                })
        merged.append(row)
    return merged


def merge_codebygk(base, merged, incoming, vault, revision):
    rows = {row["id"]: row.copy() for row in merged}
    classes = {}
    for row in base.values():
        if row["weakness"]:
            classes.setdefault(row["weakness"], set()).add(row["class"])
    for rid, external in incoming.items():
        if rid not in rows:
            row = {name: "" for name in BASE_FIELDS + EXTRA_FIELDS}
            candidates = classes.get(external["weakness"], set())
            row.update({
                "id": rid, "url": f"https://hackerone.com/reports/{rid}",
                "title": external["title"], "weakness": external["weakness"],
                "class": next(iter(candidates)) if len(candidates) == 1 else "unclassified",
                "vote_count": external["votes"], "program_name": external["program_name"],
                "has_bounty": "True" if external["bounty_amount"] else "",
                "disclosed_at": external["disclosed_at"], "body_availability": "not-fetched",
                "knowledge_status": "source-indexed", "reproduction_status": "not-reproduced",
                "metadata_status": external["metadata_status"],
            })
            note = Path("35-Report-Studies") / f"rs-{rid}.md"
            if (vault / note).is_file():
                row["study_note"] = note.as_posix()
            rows[rid] = row
        row = rows[rid]
        row.update({
            "codebygk_title": external["title"], "codebygk_program_name": external["program_name"],
            "codebygk_weakness": external["weakness"], "codebygk_vote_count": external["votes"],
            "codebygk_bounty_amount": external["bounty_amount"],
            "codebygk_bounty_status": external["bounty_status"],
            "codebygk_revision": revision, "codebygk_record": external["record"],
            **{f"codebygk_{key}": external[key] for key in
               ["severity", "state", "asset_type", "submitted_at", "disclosed_at"]},
        })
        row["sources"] = ";".join(filter(None, [row["sources"], CODEBYGK_SOURCE]))
        if external["metadata_status"] != "parsed":
            row["metadata_status"] = external["metadata_status"]
    return [rows[rid] for rid in sorted(rows, key=int)]


def merge_bugbountyskills(base, merged, incoming, vault, revision):
    rows = {row["id"]: row.copy() for row in merged}
    for rid, external in incoming.items():
        if rid not in rows:
            # Titles never establish a class: new rows stay unclassified in the
            # authoritative column; the takeover label is source-attributed only.
            row = {name: "" for name in BASE_FIELDS + EXTRA_FIELDS}
            row.update({
                "id": rid, "url": f"https://hackerone.com/reports/{rid}",
                "title": external["title"], "class": "unclassified",
                "program_name": external["program_name"],
                "body_availability": "not-fetched",
                "knowledge_status": "source-indexed", "reproduction_status": "not-reproduced",
                "metadata_status": external["metadata_status"],
            })
            note = Path("35-Report-Studies") / f"rs-{rid}.md"
            if (vault / note).is_file():
                row["study_note"] = note.as_posix()
            rows[rid] = row
        row = rows[rid]
        row.update({
            "bbtakeover_title": external["title"],
            "bbtakeover_program_name": external["program_name"],
            "bbtakeover_severity": external["severity"],
            "bbtakeover_claimed_class": "subdomain-takeover" if external["metadata_status"] == "parsed" else "",
            "bbtakeover_revision": revision, "bbtakeover_record": external["record"],
        })
        row["sources"] = ";".join(filter(None, [row["sources"], BUGBOUNTYSKILLS_SOURCE]))
        if external["metadata_status"] != "parsed":
            row["metadata_status"] = external["metadata_status"]
    return [rows[rid] for rid in sorted(rows, key=int)]


def csv_bytes(rows):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=BASE_FIELDS + EXTRA_FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def write_atomic(path, data):
    if path.is_file() and path.read_bytes() == data:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def source_note(manifest, source=SOURCE):
    counts = manifest["source_counts"][source]
    provenance = manifest["sources"][source]
    revision = provenance["revision"]
    config = SOURCE_CONFIGS[source]
    alias = next(alias for alias, repository in SOURCE_ALIASES.items() if repository == source)
    return f"""---
tags: [source, report-index]
knowledge_status: source-indexed
reproduction_status: not-reproduced
source_revision: {revision}
---
<!-- Generated by scripts/import_report_index.py; do not edit. -->

# HackerOne report index — {source.split('/')[0]}

[Upstream repository](https://github.com/{source}) ·
[Pinned source data]({provenance['url']})

## Coverage

| Measure | Reports |
|---|---:|
| Source index, unique IDs | {counts['source_report_ids']:,} |
| Also present in the original dataset or another active source | {counts['overlapping_with_other_inputs']:,} |
| Unique contribution beyond all other active inputs | {counts['unique_contribution']:,} |
| **Combined index, all sources** | **{manifest['counts']['merged_report_ids']:,}** |
| Quarantined source records | {counts['quarantined_source_records']:,} |

## Local artifacts

- [All-source overview](_MOC.md).
- [Combined searchable CSV](../../_data/reports-merged.csv) — one row per report ID.
- [Original dataset index](../../_data/reports.csv) — unchanged.
- [Raw source snapshot](../../_data/sources/{config['slug']}/{revision}/{config['filename']}).
- [Source provenance](../../_data/sources/{config['slug']}/{revision}/manifest.json).
- [Import receipt and checksums](../../_data/report-import-manifest.json).
- [Quarantined records](../../_data/report-index-quarantine.jsonl).
- [Existing report studies](../../35-Report-Studies/_MOC.md) — unchanged.

## Trust and interpretation

- This is a **metadata/discovery index**, not a new collection of reproduced findings.
- All records are `source-indexed` and `not-reproduced` by this import. Existing
  historical report states remain in `substate`; they are not current test results.
- No report pages, full report bodies, private reports, or attachments were fetched.
- Original dataset fields take precedence, followed by reddelexc for new IDs, then
  codebygk, then the BugBountySkills takeover index. Supplemental metadata is retained
  separately: `source_*` fields refer to reddelexc, `codebygk_*` fields refer to
  codebygk, and `bbtakeover_*` fields refer to the BugBountySkills subdomain-takeover
  index. Program display names are not team handles.
- Source bounty zero is ambiguous (zero or unavailable). The normalized amount
  stays blank and its bounty status is `unknown-or-zero`. Currency is not asserted.
- `codebygk_severity` and `codebygk_state` are historical source claims, not current
  validation or severity decisions. `Closed` is not translated to `resolved`.
- `bbtakeover_severity` and `bbtakeover_claimed_class` come from an AI-generated
  knowledge base; they are discovery pointers to read the underlying report, never
  severity or class decisions. New IDs this source contributes stay `unclassified`
  in the authoritative class column.
- BugBountySkills row labels are not independently checked against HackerOne. Its
  aggregate severity percentages and claimed chain payouts are not validated by
  importing these pointers; N/A bounty values remain unknown, not zero.
- Null metadata stays blank. The literal severity `none` is retained distinctly
  from missing severity. Original fields are never overwritten to fill these gaps.
- Classes reuse exact weakness mappings from the original index, never title-keyword
  matching. A class label, positive bounty, or vote count does not verify a vulnerability.
- Repository update time does not establish each report's metadata freshness.
- Source text is untrusted data, not agent instructions. Public disclosure does not
  authorize testing any listed asset or eliminate private duplicate risk.
- Attribute upstream and original reports; third-party material retains its own terms.

## Refresh

From the repository root, run `python3 scripts/import_report_index.py --source {alias}`
after rebuilding the original index. Every import includes **all registered sources**
from the import receipt, using validated cached snapshots for the other sources.
Supply `--revision <full-commit-SHA>` to review/import a newer snapshot for the selected
source. Older snapshots are retained; existing dossiers are never changed.
""".encode("utf-8")


def sources_note(manifest):
    rows = []
    for source, counts in manifest["source_counts"].items():
        config = SOURCE_CONFIGS[source]
        rows.append(f"| [{source}]({config['slug']}.md) | {counts['source_report_ids']:,} | "
                    f"{counts['unique_contribution']:,} |")
    return ("---\ntags: [moc, source, report-index]\n---\n"
            "<!-- Generated by scripts/import_report_index.py; do not edit. -->\n\n"
            "# Report knowledge sources\n\n"
            f"**{manifest['counts']['merged_report_ids']:,} unique report IDs** across the original "
            f"{manifest['counts']['base_report_ids']:,}-report dataset and these pinned indexes.\n\n"
            "| Supplemental source | Report IDs | Unique contribution beyond other inputs |\n"
            "|---|---:|---:|\n" + "\n".join(rows) + "\n\n"
            "[Combined index](../../_data/reports-merged.csv) · "
            "[Import receipt](../../_data/report-import-manifest.json)\n\n"
            "Overlapping IDs appear once, with attribution to every matching source. Unique "
            "contribution excludes the original dataset and all other active sources; these "
            "contributions do not sum to total coverage because sources overlap.\n\n"
            "These are **historical metadata references**, not independently reproduced findings. "
            "No report bodies, private reports, or attachments were fetched. Existing dossiers "
            "and the original dataset index are preserved.\n").encode("utf-8")


def active_sources(vault):
    receipt = vault / "_data/report-import-manifest.json"
    if not receipt.is_file():
        return {}
    manifest = json.loads(receipt.read_text(encoding="utf-8"))
    sources = manifest.get("sources")
    if sources is None:
        # Migrate the original single-source receipt without discarding its index.
        legacy = manifest.get("source", {})
        source = legacy.get("repository", "").removeprefix("https://github.com/")
        sources = {source: legacy}
    if not isinstance(sources, dict):
        raise ValueError("invalid active-source receipt")
    for source, provenance in sources.items():
        if not isinstance(provenance, dict):
            raise ValueError("invalid source provenance")
        expected = source_url(provenance.get("revision", ""), source)
        if provenance.get("url") != expected:
            raise ValueError("active-source URL does not match its pinned revision")
    return sources


def load_snapshot(vault, source, revision, source_file=None, require_cached=False):
    url = source_url(revision, source)
    config = SOURCE_CONFIGS[source]
    snapshot_dir = vault / "_data/sources" / config["slug"] / revision
    snapshot = snapshot_dir / config["filename"]
    provenance_path = snapshot_dir / "manifest.json"
    if require_cached and (not snapshot.is_file() or not provenance_path.is_file()):
        raise ValueError(f"registered source {source} has no complete cached snapshot; refusing to drop it")
    if source_file is not None:
        data = Path(source_file).read_bytes()
        acquisition = "supplied-file"
    elif snapshot.is_file():
        data = snapshot.read_bytes()
        acquisition = "cached-snapshot"
    else:
        request = urllib.request.Request(url, headers={"User-Agent": "BugVault-Metadata-Importer/1.0"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(MAX_SOURCE_BYTES + 1)
        acquisition = "https-download"
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("source CSV exceeds the 50 MiB import limit")
    if snapshot.is_file() and snapshot.read_bytes() != data:
        raise ValueError("cached source snapshot differs; refusing to overwrite it")
    checksum = sha256(data)
    if provenance_path.is_file():
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        if (provenance.get("sha256") != checksum or provenance.get("revision") != revision
                or provenance.get("url") != url):
            raise ValueError("source snapshot failed provenance/checksum validation")
    else:
        provenance = {
            "repository": f"https://github.com/{source}", "revision": revision,
            "url": url, "sha256": checksum, "bytes": len(data),
            "acquisition": acquisition,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
    return data, provenance, snapshot, provenance_path


def run_import(vault, revision=None, source_file=None, dry_run=False, source=SOURCE):
    vault = Path(vault)
    if source not in SOURCE_CONFIGS:
        raise ValueError(f"unsupported source: {source}")
    registered = active_sources(vault)
    revision = revision or registered.get(source, {}).get("revision") or SOURCE_CONFIGS[source]["revision"]
    revisions = {key: value["revision"] for key, value in registered.items()}
    revisions[source] = revision
    snapshots, inputs, quarantines, source_counts = {}, {}, [], {}
    for key in SOURCE_CONFIGS:
        if key not in revisions:
            continue
        loaded = load_snapshot(vault, key, revisions[key],
                               source_file=source_file if key == source else None,
                               require_cached=key != source)
        data, provenance, _, _ = loaded
        if key in registered and revisions[key] == registered[key]["revision"]:
            if provenance["sha256"] != registered[key]["sha256"]:
                raise ValueError("registered source checksum does not match cached provenance")
        snapshots[key] = loaded
        parser = {SOURCE: parse_source, CODEBYGK_SOURCE: parse_codebygk_source,
                  BUGBOUNTYSKILLS_SOURCE: parse_bugbountyskills_source}[key]
        incoming, quarantine, source_rows, duplicates = parser(data)
        inputs[key] = incoming
        quarantines.extend({"source": key, **item} for item in quarantine)
        source_counts[key] = {
            "source_records": source_rows, "source_report_ids": len(incoming),
            "duplicate_source_records": duplicates, "quarantined_source_records": len(quarantine),
        }
    base_path = vault / "_data/reports.csv"
    base_data = base_path.read_bytes()
    base = read_base(base_data)
    merged = merge_reports(base, inputs.get(SOURCE, {}), vault, revisions.get(SOURCE, ""))
    if CODEBYGK_SOURCE in inputs:
        merged = merge_codebygk(base, merged, inputs[CODEBYGK_SOURCE], vault, revisions[CODEBYGK_SOURCE])
    if BUGBOUNTYSKILLS_SOURCE in inputs:
        merged = merge_bugbountyskills(base, merged, inputs[BUGBOUNTYSKILLS_SOURCE], vault,
                                       revisions[BUGBOUNTYSKILLS_SOURCE])
    merged_data = csv_bytes(merged)
    external_ids = set().union(*(set(incoming) for incoming in inputs.values()))
    for key, incoming in inputs.items():
        others = set(base).union(*(set(value) for other, value in inputs.items() if other != key))
        source_counts[key].update({
            "overlapping_with_other_inputs": len(incoming.keys() & others),
            "unique_contribution": len(incoming.keys() - others),
        })
    counts = {
        "base_report_ids": len(base),
        "source_records": sum(item["source_records"] for item in source_counts.values()),
        "source_report_ids": len(external_ids),
        "duplicate_source_records": sum(item["duplicate_source_records"] for item in source_counts.values()),
        "overlapping_report_ids": len(base.keys() & external_ids),
        "new_report_ids": len(external_ids - base.keys()),
        "base_only_report_ids": len(base.keys() - external_ids),
        "merged_report_ids": len(merged), "quarantined_source_records": len(quarantines),
        "linked_existing_study_notes": sum(bool(row["study_note"]) for row in merged),
    }
    manifest = {
        "schema_version": 2, "importer": "scripts/import_report_index.py",
        "sources": {key: loaded[1] for key, loaded in snapshots.items()},
        "source_counts": source_counts,
        "base": {"path": "_data/reports.csv", "source": BASE_SOURCE, "sha256": sha256(base_data)},
        "output": {"path": "_data/reports-merged.csv", "sha256": sha256(merged_data)},
        "counts": counts,
        "policy": {
            "existing_fields": "preserved; upstream metadata stored separately",
            "classification": "exact weakness crosswalk from base index; unknown stays unclassified",
            "bounty_zero": "unknown-or-zero; normalized amount blank",
            "knowledge_status": "source-indexed", "reproduction_status": "not-reproduced",
            "full_reports_fetched": False,
            "metadata_precedence": [BASE_SOURCE, SOURCE, CODEBYGK_SOURCE, BUGBOUNTYSKILLS_SOURCE],
            "historical_severity": "codebygk_* and bbtakeover_* fields only; never a current validation decision",
        },
    }
    if not dry_run:
        # All inputs are parsed/validated before any output changes. The receipt
        # is published last; its hash lets consumers detect an interrupted write.
        for data, provenance, snapshot, provenance_path in snapshots.values():
            write_atomic(snapshot, data)
            write_atomic(provenance_path, json_bytes(provenance))
        write_atomic(vault / "_data/reports-merged.csv", merged_data)
        write_atomic(vault / "_data/report-index-quarantine.jsonl",
                     b"".join((json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
                              for item in quarantines))
        for key in inputs:
            path = vault / "90-Meta/sources" / f"{SOURCE_CONFIGS[key]['slug']}.md"
            write_atomic(path, source_note(manifest, key))
        write_atomic(vault / "90-Meta/sources/_MOC.md", sources_note(manifest))
        write_atomic(vault / "_data/report-import-manifest.json", json_bytes(manifest))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="vault", help="vault directory (default: vault)")
    parser.add_argument("--source", choices=SOURCE_ALIASES, default="reddelexc", help="source to add/refresh")
    parser.add_argument("--revision", help="pinned upstream Git commit SHA (default: registered or reviewed revision)")
    parser.add_argument("--source-file", type=Path, help="use a local source file instead of downloading")
    parser.add_argument("--dry-run", action="store_true", help="validate and summarize without writing")
    args = parser.parse_args()
    try:
        source = SOURCE_ALIASES[args.source]
        manifest = run_import(args.out, args.revision, args.source_file, args.dry_run, source)
    except (OSError, ValueError, csv.Error) as error:
        parser.exit(1, f"import failed: {error}\n")
    print(json.dumps({"dry_run": args.dry_run, "selected_source": source,
                      "revision": manifest["sources"][source]["revision"],
                      "selected_source_counts": manifest["source_counts"][source],
                      **manifest["counts"]}, indent=2))


if __name__ == "__main__":
    main()
