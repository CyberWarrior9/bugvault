import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import import_report_index as importer


def source_csv(rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(importer.SOURCE_FIELDS)
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def original_row(rid="1"):
    return dict(zip(importer.BASE_FIELDS, [
        rid, "Original title", f"https://hackerone.com/reports/{rid}", "resolved",
        "Information Disclosure", "info-disclosure", "original-handle", "False",
        "3", "2024-01-01", "100",
    ]))


def codebygk_row(rid="3", **overrides):
    return {
        "title": "Historical title", "url": f"https://hackerone.com/reports/{rid}",
        "program": "Historical program", "asset_type": "URL", "bounty": 0.0,
        "vulnerability_type": "Information Disclosure", "severity": "high", "state": "Closed",
        "upvotes": 10, "submitted_at": "2023-01-01T00:00:00Z",
        "disclosed_at": "2024-01-01T00:00:00Z", **overrides,
    }


def codebygk_json(rows):
    return json.dumps({"reports": rows}, ensure_ascii=False).encode("utf-8")


class ParseTests(unittest.TestCase):
    def test_doubled_quotes_and_commas_are_valid_csv(self):
        data = source_csv([["Program", 'A "quoted", comma-containing title',
                            "hackerone.com/reports/2", 10, "0.0", "Information Disclosure"]])
        rows, quarantine, count, duplicates = importer.parse_source(data)
        self.assertEqual(rows["2"]["title"], 'A "quoted", comma-containing title')
        self.assertEqual((quarantine, count, duplicates), ([], 1, 0))

    def test_unknown_bounty_is_not_false_or_zero(self):
        data = source_csv([["Program", "Title", "hackerone.com/reports/2", 0, "0.0", ""]])
        rows, _, _, _ = importer.parse_source(data)
        self.assertEqual(rows["2"]["bounty_amount"], "")
        self.assertEqual(rows["2"]["bounty_status"], "unknown-or-zero")

    def test_positive_bounty_is_retained_as_reported(self):
        data = source_csv([["Program", "Title", "hackerone.com/reports/2", 0, "1234.50", ""]])
        rows, _, _, _ = importer.parse_source(data)
        self.assertEqual(rows["2"]["bounty_amount"], "1234.50")
        self.assertEqual(rows["2"]["bounty_status"], "reported-positive")

    def test_malformed_fields_are_quarantined_without_guessing(self):
        data = source_csv([["Program", "Broken", "extra", "hackerone.com/reports/2", 1, 0, ""]])
        rows, quarantine, _, _ = importer.parse_source(data)
        self.assertEqual(len(quarantine), 1)
        self.assertEqual(rows["2"]["metadata_status"], "external-quarantined")
        self.assertEqual(rows["2"]["title"], "")

    def test_ambiguous_malformed_record_is_not_indexed(self):
        data = source_csv([["hackerone.com/reports/2", "hackerone.com/reports/3", "bad"]])
        rows, quarantine, _, _ = importer.parse_source(data)
        self.assertEqual(rows, {})
        self.assertEqual(len(quarantine), 1)

    def test_invalid_metadata_is_quarantined(self):
        for votes, bounty in [("bad", "0"), ("1", "NaN"), ("1", "Infinity"), ("1", "-1")]:
            with self.subTest(votes=votes, bounty=bounty):
                rows, quarantine, _, _ = importer.parse_source(source_csv([
                    ["Program", "Title", "hackerone.com/reports/2", votes, bounty, ""]]))
                self.assertEqual(len(quarantine), 1)
                self.assertEqual(rows["2"]["metadata_status"], "external-quarantined")

    def test_report_link_validation(self):
        self.assertEqual(importer.report_id("hackerone.com/reports/123?tracking=1"), "123")
        for link in ["https://evil.test/reports/1", "https://hackerone.com.evil.test/reports/1",
                     "https://user@hackerone.com/reports/1", "https://hackerone.com/reports/../1",
                     "https://hackerone.com/reports/01"]:
            with self.subTest(link=link), self.assertRaises(ValueError):
                importer.report_id(link)

    def test_identical_duplicates_deduplicate_but_conflicts_abort(self):
        row = ["Program", "Title", "hackerone.com/reports/2", 0, "0", ""]
        rows, _, count, duplicates = importer.parse_source(source_csv([row, row]))
        self.assertEqual((len(rows), count, duplicates), (1, 2, 1))
        other = row.copy()
        other[1] = "Different title"
        with self.assertRaisesRegex(ValueError, "conflicting"):
            importer.parse_source(source_csv([row, other]))

    def test_header_drift_aborts(self):
        with self.assertRaisesRegex(ValueError, "header"):
            importer.parse_source(b"wrong,header\n")


class CodebygkParseTests(unittest.TestCase):
    def test_historical_metadata_is_retained(self):
        rows, quarantine, count, duplicates = importer.parse_codebygk_source(
            codebygk_json([codebygk_row(bounty=1234.5)]))
        self.assertEqual((quarantine, count, duplicates), ([], 1, 0))
        self.assertEqual(rows["3"]["severity"], "high")
        self.assertEqual(rows["3"]["state"], "Closed")
        self.assertEqual(rows["3"]["asset_type"], "URL")
        self.assertEqual(rows["3"]["bounty_amount"], "1234.5")

    def test_nulls_stay_unknown_and_none_label_is_distinct(self):
        rows, quarantine, _, _ = importer.parse_codebygk_source(codebygk_json([
            codebygk_row(title=None, severity=None, state=None, submitted_at=None, disclosed_at=None),
            codebygk_row("4", severity="none"),
        ]))
        self.assertEqual(quarantine, [])
        self.assertEqual(rows["3"]["title"], "")
        self.assertEqual(rows["3"]["severity"], "")
        self.assertEqual(rows["3"]["disclosed_at"], "")
        self.assertEqual(rows["4"]["severity"], "none")
        self.assertEqual(rows["3"]["bounty_amount"], "")
        self.assertEqual(rows["3"]["bounty_status"], "unknown-or-zero")

    def test_schema_drift_aborts(self):
        for payload in [[], {"reports": {}}, {"other": []}]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                importer.parse_codebygk_source(json.dumps(payload).encode())

    def test_invalid_metadata_is_quarantined(self):
        for fields in [{"upvotes": True}, {"upvotes": -1}, {"bounty": float("nan")},
                       {"bounty": -1}, {"severity": []}]:
            with self.subTest(fields=fields):
                rows, quarantine, _, _ = importer.parse_codebygk_source(
                    codebygk_json([codebygk_row(**fields)]))
                self.assertEqual(len(quarantine), 1)
                self.assertEqual(rows["3"]["metadata_status"], "external-quarantined")
                self.assertEqual(rows["3"]["title"], "")

    def test_unidentifiable_reports_are_not_indexed(self):
        rows, quarantine, _, _ = importer.parse_codebygk_source(codebygk_json([
            None, codebygk_row(url="https://evil.test/reports/3"),
        ]))
        self.assertEqual(rows, {})
        self.assertEqual(len(quarantine), 2)

    def test_identical_duplicates_deduplicate_and_conflicts_abort(self):
        row = codebygk_row()
        rows, _, count, duplicates = importer.parse_codebygk_source(codebygk_json([row, row]))
        self.assertEqual((len(rows), count, duplicates), (1, 2, 1))
        with self.assertRaisesRegex(ValueError, "conflicting"):
            importer.parse_codebygk_source(codebygk_json([row, codebygk_row(title="Changed")]))


class TakeoverParseTests(unittest.TestCase):
    @staticmethod
    def takeover_md(rows):
        lines = ["---", "vuln_type: \"Subdomain_Takeover\"", "---", "",
                 "| ID | Title | Program | Severity | Bounty | Sub-type | Quality | URL |",
                 "|----|-------|---------|----------|--------|----------|---------|-----|"]
        for rid, title, program, severity in rows:
            lines.append(f"| {rid} | {title} | {program} | {severity} | N/A | General | 9 | "
                         f"[link](https://hackerone.com/reports/{rid}) |")
        return ("\n".join(lines) + "\n").encode("utf-8")

    def test_table_rows_are_retained_as_attributed_claims(self):
        rows, quarantine, count, duplicates = importer.parse_bugbountyskills_source(
            self.takeover_md([("2542372", "FULL ACCOUNT TAKEOVER", "MTN Group", "critical")]))
        self.assertEqual((quarantine, count, duplicates), ([], 1, 0))
        self.assertEqual(rows["2542372"]["title"], "FULL ACCOUNT TAKEOVER")
        self.assertEqual(rows["2542372"]["program_name"], "MTN Group")
        self.assertEqual(rows["2542372"]["severity"], "critical")

    def test_header_separator_and_frontmatter_are_ignored(self):
        rows, quarantine, count, _ = importer.parse_bugbountyskills_source(
            self.takeover_md([("1180697", "Subdomain takeover of v.zego.com", "Zego", "low")]))
        self.assertEqual((len(rows), len(quarantine), count), (1, 0, 1))

    def test_invalid_rows_are_quarantined(self):
        lines = ["| ID | Title | Program | Severity | Bounty | Sub-type | Quality | URL |",
                 "|----|-------|---------|----------|--------|----------|---------|-----|",
                 "| 999 | Title | Program | critical | N/A | General | 9 | evil-link-not-a-report |",
                 "| 12345 | Missing cells |",  # wrong field count
                 "| 777 | T | P | catastrophic | N/A | General | 9 | "
                 "[link](https://hackerone.com/reports/777) |"]  # unknown severity
        rows, quarantine, count, _ = importer.parse_bugbountyskills_source(
            ("\n".join(lines) + "\n").encode())
        self.assertEqual(len(quarantine), 3)
        self.assertEqual(count, 3)
        # unidentifiable rows are not indexed; the identifiable one is indexed blanked
        self.assertNotIn("999", rows)
        self.assertNotIn("12345", rows)
        self.assertEqual(rows["777"]["metadata_status"], "external-quarantined")
        self.assertEqual(rows["777"]["title"], "")

    def test_id_link_disagreement_is_quarantined(self):
        lines = ["| ID | Title | Program | Severity | Bounty | Sub-type | Quality | URL |",
                 "|----|-------|---------|----------|--------|----------|---------|-----|",
                 "| 111 | Title | Program | low | N/A | General | 9 | "
                 "[link](https://hackerone.com/reports/222) |"]
        rows, quarantine, _, _ = importer.parse_bugbountyskills_source(
            ("\n".join(lines) + "\n").encode())
        self.assertEqual(rows, {})
        self.assertEqual(len(quarantine), 1)

    def test_identical_duplicates_deduplicate_and_conflicts_abort(self):
        payload = self.takeover_md([("100", "T", "P", "low"), ("100", "T", "P", "low")])
        rows, _, count, duplicates = importer.parse_bugbountyskills_source(payload)
        self.assertEqual((len(rows), count, duplicates), (1, 2, 1))
        conflicting = self.takeover_md([("100", "T", "P", "low"), ("100", "Other", "P", "low")])
        with self.assertRaisesRegex(ValueError, "conflicting"):
            importer.parse_bugbountyskills_source(conflicting)

    def test_missing_or_changed_header_and_empty_table_abort(self):
        valid = self.takeover_md([("100", "T", "P", "low")])
        for payload in (b"not a report table", self.takeover_md([]),
                        valid.replace(b"| ID | Title |", b"| ID | Changed |")):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                importer.parse_bugbountyskills_source(payload)

    def test_invalid_duplicate_cannot_overwrite_valid_metadata(self):
        for labels in (("low", "invalid"), ("invalid", "low")):
            payload = self.takeover_md([("100", "T", "P", label) for label in labels])
            with self.subTest(labels=labels), self.assertRaisesRegex(ValueError, "conflicting"):
                importer.parse_bugbountyskills_source(payload)


class MergeTests(unittest.TestCase):
    def test_takeover_metadata_does_not_overwrite_prior_fields(self):
        incoming, _, _, _ = importer.parse_bugbountyskills_source(TakeoverParseTests.takeover_md([
            ("1", "Source claim", "Source program", "critical"),
            ("5", "New pointer", "New program", "low"),
        ]))
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            base = {"1": original_row()}
            before = importer.merge_reports(base, {}, vault, "")
            after = {row["id"]: row for row in importer.merge_bugbountyskills(
                base, before, incoming, vault, importer.BUGBOUNTYSKILLS_REVISION)}
        for field, value in before[0].items():
            if field != "sources" and not field.startswith("bbtakeover_"):
                self.assertEqual(after["1"][field], value)
        self.assertEqual(after["1"]["bbtakeover_severity"], "critical")
        self.assertEqual(after["5"]["class"], "unclassified")
        self.assertEqual(after["5"]["has_bounty"], "")
        self.assertEqual(after["5"]["reproduction_status"], "not-reproduced")

    def test_original_fields_preserved_and_source_fields_separated(self):
        incoming, _, _, _ = importer.parse_source(source_csv([
            ["New program name", "Changed title", "hackerone.com/reports/1", 99, "1000", "SQL Injection"],
            ["Other program", "RCE is only mentioned", "hackerone.com/reports/2", 5, "0", "Unknown weakness"],
            ["Other program", "Data issue", "hackerone.com/reports/3", 1, "0", "Information Disclosure"],
        ]))
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            note = vault / "35-Report-Studies/rs-1.md"
            note.parent.mkdir()
            note.write_text("Human-maintained dossier", encoding="utf-8")
            original = original_row()
            rows = {row["id"]: row for row in importer.merge_reports(
                {"1": original}, incoming, vault, importer.DEFAULT_REVISION)}
            for key, value in original.items():
                self.assertEqual(rows["1"][key], value)
            self.assertEqual(rows["1"]["program_name"], "New program name")
            self.assertEqual(rows["1"]["source_title"], "Changed title")
            self.assertEqual(rows["1"]["source_vote_count"], "99")
            self.assertEqual(rows["1"]["study_note"], "35-Report-Studies/rs-1.md")
            self.assertEqual(rows["2"]["class"], "unclassified")
            self.assertEqual(rows["2"]["has_bounty"], "")
            self.assertEqual(rows["2"]["substate"], "")
            self.assertEqual(rows["2"]["body_chars"], "")
            self.assertEqual(rows["3"]["class"], "info-disclosure")
            for row in rows.values():
                self.assertEqual(row["reproduction_status"], "not-reproduced")
                self.assertEqual(row["knowledge_status"], "source-indexed")

    def test_codebygk_enriches_without_overwriting_prior_metadata(self):
        reddelexc, _, _, _ = importer.parse_source(source_csv([
            ["Red program", "Red title", "hackerone.com/reports/2", 15, "1000", "Information Disclosure"],
        ]))
        codebygk, _, _, _ = importer.parse_codebygk_source(codebygk_json([
            codebygk_row("1"), codebygk_row("2"), codebygk_row("3", severity="critical"),
        ]))
        with tempfile.TemporaryDirectory() as directory:
            vault = Path(directory)
            base = {"1": original_row()}
            before = importer.merge_reports(base, reddelexc, vault, importer.DEFAULT_REVISION)
            after = {row["id"]: row for row in importer.merge_codebygk(
                base, before, codebygk, vault, importer.CODEBYGK_REVISION)}
        for original in before:
            for key, value in original.items():
                if key != "sources" and not key.startswith("codebygk_"):
                    self.assertEqual(after[original["id"]][key], value)
        self.assertEqual(after["2"]["source_title"], "Red title")
        self.assertEqual(after["2"]["codebygk_title"], "Historical title")
        self.assertEqual(after["3"]["substate"], "")
        self.assertEqual(after["3"]["codebygk_state"], "Closed")
        self.assertEqual(after["3"]["codebygk_severity"], "critical")
        self.assertEqual(after["3"]["reproduction_status"], "not-reproduced")
        self.assertEqual(after["3"]["body_chars"], "")
        self.assertEqual(after["3"]["has_bounty"], "")
        self.assertEqual(after["3"]["class"], "info-disclosure")


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.vault = self.root / "vault"
        self.base_path = self.vault / "_data/reports.csv"
        self.base_path.parent.mkdir(parents=True)
        with self.base_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=importer.BASE_FIELDS)
            writer.writeheader()
            writer.writerow(original_row())
        self.source = self.root / "source.csv"
        self.source.write_bytes(source_csv([
            ["Program", "Title", "hackerone.com/reports/1", 10, "0", "Information Disclosure"],
            ["Program", 'New "quoted", title', "hackerone.com/reports/2", 5, "0", "Information Disclosure"],
        ]))

    def file_hashes(self):
        return {p.relative_to(self.vault).as_posix(): importer.sha256(p.read_bytes())
                for p in self.vault.rglob("*") if p.is_file()}

    def test_dry_run_writes_nothing(self):
        before = self.file_hashes()
        manifest = importer.run_import(self.vault, source_file=self.source, dry_run=True)
        self.assertEqual(manifest["counts"]["new_report_ids"], 1)
        self.assertEqual(self.file_hashes(), before)

    def test_cached_rerun_is_idempotent_and_original_is_unchanged(self):
        base_before = self.base_path.read_bytes()
        first = importer.run_import(self.vault, source_file=self.source)
        before = self.file_hashes()
        second = importer.run_import(self.vault)
        self.assertEqual(first, second)
        self.assertEqual(self.file_hashes(), before)
        self.assertEqual(self.base_path.read_bytes(), base_before)
        self.assertEqual(first["counts"]["merged_report_ids"], 2)
        merged = self.vault / "_data/reports-merged.csv"
        self.assertEqual(first["output"]["sha256"], importer.sha256(merged.read_bytes()))

    def test_changed_snapshot_is_never_overwritten(self):
        importer.run_import(self.vault, source_file=self.source)
        before = self.file_hashes()
        self.source.write_bytes(source_csv([["X", "Changed", "hackerone.com/reports/2", 1, 0, ""]]))
        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            importer.run_import(self.vault, source_file=self.source)
        self.assertEqual(self.file_hashes(), before)

    def test_corrupted_cached_snapshot_aborts(self):
        importer.run_import(self.vault, source_file=self.source)
        snapshot = (self.vault / "_data/sources/reddelexc-hackerone-reports"
                    / importer.DEFAULT_REVISION / "data.csv")
        snapshot.write_bytes(snapshot.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "checksum"):
            importer.run_import(self.vault)

    def test_invalid_input_does_not_publish_partial_outputs(self):
        before = self.file_hashes()
        self.source.write_bytes(b"invalid,header\n")
        with self.assertRaises(ValueError):
            importer.run_import(self.vault, source_file=self.source)
        self.assertEqual(self.file_hashes(), before)

    def test_revision_must_be_pinned(self):
        with self.assertRaises(ValueError):
            importer.run_import(self.vault, revision="master", source_file=self.source)

    def add_codebygk(self):
        source = self.root / "reports.json"
        source.write_bytes(codebygk_json([codebygk_row("1"), codebygk_row("3")]))
        return importer.run_import(self.vault, source_file=source, source=importer.CODEBYGK_SOURCE)

    def add_takeover(self, dry_run=False):
        source = self.root / "takeover.md"
        source.write_bytes(TakeoverParseTests.takeover_md([
            ("1", "Original pointer", "P", "low"), ("4", "New pointer", "P", "high"),
        ]))
        return importer.run_import(self.vault, source_file=source, dry_run=dry_run,
                                   source=importer.BUGBOUNTYSKILLS_SOURCE)

    def test_takeover_and_other_sources_survive_cached_reruns(self):
        base_before = self.base_path.read_bytes()
        importer.run_import(self.vault, source_file=self.source)
        self.add_codebygk()
        manifest = self.add_takeover()
        before = self.file_hashes()
        self.assertEqual(manifest["counts"]["merged_report_ids"], 4)
        for source in importer.SOURCE_CONFIGS:
            self.assertEqual(importer.run_import(self.vault, source=source), manifest)
        self.assertEqual(self.file_hashes(), before)
        self.assertEqual(self.base_path.read_bytes(), base_before)
        note = self.vault / "90-Meta/sources/bugbountyskills-subdomain-takeover.md"
        self.assertIn("--source takeover", note.read_text())

    def test_takeover_dry_run_writes_nothing(self):
        before = self.file_hashes()
        manifest = self.add_takeover(dry_run=True)
        self.assertEqual(manifest["counts"]["merged_report_ids"], 2)
        self.assertEqual(self.file_hashes(), before)

    def test_invalid_takeover_envelope_does_not_publish(self):
        before = self.file_hashes()
        source = self.root / "invalid.md"
        source.write_text("not a report table")
        with self.assertRaises(ValueError):
            importer.run_import(self.vault, source_file=source,
                                source=importer.BUGBOUNTYSKILLS_SOURCE)
        self.assertEqual(self.file_hashes(), before)

    def test_multiple_sources_survive_reruns_of_either_source(self):
        importer.run_import(self.vault, source_file=self.source)
        combined = self.add_codebygk()
        self.assertEqual(combined["counts"]["merged_report_ids"], 3)
        self.assertEqual(combined["source_counts"][importer.CODEBYGK_SOURCE]["unique_contribution"], 1)
        before = self.file_hashes()
        self.assertEqual(importer.run_import(self.vault), combined)
        self.assertEqual(importer.run_import(self.vault, source=importer.CODEBYGK_SOURCE), combined)
        self.assertEqual(self.file_hashes(), before)

    def test_legacy_single_source_receipt_is_migrated(self):
        first = importer.run_import(self.vault, source_file=self.source)
        receipt = self.vault / "_data/report-import-manifest.json"
        receipt.write_text(json.dumps({"schema_version": 1, "source": first["sources"][importer.SOURCE]}))
        combined = self.add_codebygk()
        self.assertEqual(set(combined["sources"]), {importer.SOURCE, importer.CODEBYGK_SOURCE})
        self.assertEqual(combined["counts"]["merged_report_ids"], 3)

    def test_missing_other_source_snapshot_never_silently_drops_reports(self):
        importer.run_import(self.vault, source_file=self.source)
        self.add_codebygk()
        snapshot = (self.vault / "_data/sources/codebygk-hackerone-bug-bounty-reports"
                    / importer.CODEBYGK_REVISION / "reports.json")
        snapshot.unlink()
        before = self.file_hashes()
        with self.assertRaisesRegex(ValueError, "refusing to drop"):
            importer.run_import(self.vault)
        self.assertEqual(self.file_hashes(), before)

    def test_codebygk_only_import_works_without_reddelexc(self):
        manifest = self.add_codebygk()
        self.assertEqual(set(manifest["sources"]), {importer.CODEBYGK_SOURCE})
        self.assertEqual(manifest["counts"]["merged_report_ids"], 2)

    def test_multi_source_dry_run_writes_nothing(self):
        importer.run_import(self.vault, source_file=self.source)
        source = self.root / "reports.json"
        source.write_bytes(codebygk_json([codebygk_row()]))
        before = self.file_hashes()
        manifest = importer.run_import(self.vault, source_file=source, dry_run=True,
                                       source=importer.CODEBYGK_SOURCE)
        self.assertEqual(manifest["counts"]["merged_report_ids"], 3)
        self.assertEqual(self.file_hashes(), before)


if __name__ == "__main__":
    unittest.main()
