"""Smuggling skill wiring and offline-only review boundaries, not protocol tests."""
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from recon.catalog import catalog
from recon.pipeline import Recon
from recon.report import write_reports
from recon.score import applicable_classes
from recon.skillmap import skill_path, skills_for, seeded_by
from tests.test_recon import write_campaign


class HttpSmugglingSkillTests(unittest.TestCase):
    def setUp(self):
        self.path = skill_path("hunt-http-smuggling")
        self.text = self.path.read_text(encoding="utf-8")
        self.refs = "\n".join(p.read_text(encoding="utf-8")
                              for p in (self.path.parent / "references").glob("*.md"))

    def test_catalog_and_routing_are_skill_only(self):
        self.assertEqual(skills_for("http-smuggling"), ("hunt-http-smuggling",))
        self.assertEqual(seeded_by("http-smuggling"), "score.py")
        entry = next(e for e in catalog()["hunt_skills"] if e["id"] == "hunt-http-smuggling")
        self.assertEqual(entry["coverage_classes"], ["http-smuggling"])
        self.assertIn("no raw transport", entry["summary"])
        self.assertNotIn("smuggle", catalog()["job_needs"])

    def test_only_explicit_boolean_operator_designation_seeds(self):
        for attrs in ({}, {"tags": ["cloudfront", "nginx"], "http_version": "HTTP/2"},
                      {"http_smuggling_review": "true"}, {"http_smuggling_review": 1},
                      {"http_smuggling_review": False}):
            with self.subTest(attrs=attrs):
                self.assertNotIn("http-smuggling", applicable_classes({
                    "value": "https://acme.test/normal", "attrs": attrs}))
        reason = applicable_classes({"value": "https://acme.test/normal",
                                     "attrs": {"http_smuggling_review": True}})["http-smuggling"]
        self.assertIn("operator-designated", reason)
        self.assertIn("unverified", reason)

    def test_designated_coverage_is_untested_offline_and_names_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            camp = write_campaign(Path(tmp) / "camp", "active", [], in_scope=["acme.test"])
            ctx = Recon(camp, log=lambda _: None)
            try:
                with patch("socket.socket", side_effect=AssertionError("offline only")):
                    ctx.add_endpoint("https://acme.test/review", "manual", method="POST",
                                     extra={"http_smuggling_review": True})
                    ctx.refresh_coverage()
                    rows = [r for r in ctx.store.coverage() if r["bug_class"] == "http-smuggling"]
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["status"], "untested")
                    reports = write_reports(ctx)
                    coverage = next(p for p in reports if p.name == "coverage.md").read_text()
                self.assertIn("| http-smuggling |", coverage)
                self.assertIn("hunt-http-smuggling", coverage)
                self.assertEqual(ctx.store.jobs(), [])
                self.assertEqual(ctx.store.network_attempts(), 0)
            finally:
                ctx.store.close()

    def test_relative_references_exist_and_stay_in_skill(self):
        for target in re.findall(r"\]\((references/[^)]+)\)", self.text):
            path = (self.path.parent / target).resolve()
            self.assertTrue(path.is_relative_to(self.path.parent.resolve()))
            self.assertTrue(path.is_file(), target)
        self.assertLess(len(self.text.splitlines()), 500)

    def test_controls_attribution_and_transport_limits_are_explicit(self):
        combined = (self.text + self.refs).lower()
        for needle in ("scope-policy", "negative control", "positive control", "fresh",
                       "cl.te", "te.cl", "te.te", "h2.cl", "h2.te", "cl.0", "0.cl",
                       "client-side", "connection", "stream", "sha-256", "inconclusive",
                       "isolated", "cleanup owner", "not a byte-exact", "header names",
                       "no target executor", "automatic finding promotion", "429",
                       "resume", "real-user", "not safe", "unknown"):
            with self.subTest(needle=needle):
                self.assertIn(needle, combined)
        self.assertNotRegex(combined, r"python3 -m recon (?:smuggle|smuggling)\b")
        self.assertNotRegex(combined, r"(?:import socket|socket\.socket|nc -|curl -)")

    def test_behavioral_cases_follow_plugin_eval_layout(self):
        cases = sorted((self.path.parent / "evals").iterdir())
        self.assertEqual(len(cases), 3)
        for case in cases:
            with self.subTest(case=case.name):
                prompt = (case / "prompt.md").read_text()
                settings = (case / "case.yaml").read_text()
                self.assertTrue(prompt.startswith("---\n"))
                self.assertIn('schema_version: "1.1"', settings)
                self.assertIn("name: " + case.name, settings)
                self.assertTrue(list((case / "graders").glob("*.md")))


if __name__ == "__main__":
    unittest.main()
