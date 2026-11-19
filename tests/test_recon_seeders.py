"""Seeding is spread across modules; these tests keep the map honest.

`score.py` applicable_classes used to be the only seeder. Evidence-based classes
now seed from the module that observes the evidence (cloud.py, jsintel.py,
jsledger.py, takeover.py, pipeline.py), so a reader auditing coverage from
`applicable_classes` alone gets an incomplete answer. `skillmap.SEEDED_BY` records
where each class is seeded; this file asserts it does not drift.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.catalog import HUNT_SKILLS
from recon.findings import CHAIN_HINTS
from recon.skillmap import (FINDING_ONLY_CLASSES, SEEDED_BY, SKILLS_FOR_CLASS,
                            seeded_by, skill_path)

REPO = Path(__file__).resolve().parents[1]
RECON = REPO / "recon"


def score_classes():
    """Classes `score.py` writes into applicable_classes."""
    text = (RECON / "score.py").read_text(encoding="utf-8")
    return set(re.findall(r'out\[\s*"([a-z0-9-]+)"\s*\]', text)) | \
        set(re.findall(r'out\.setdefault\(\s*"([a-z0-9-]+)"', text))


class SeederMapTests(unittest.TestCase):
    def test_every_routed_class_has_a_recorded_seeder(self):
        """A routed class with no seeder would render a skill nobody can reach."""
        missing = sorted(set(SKILLS_FOR_CLASS) - set(SEEDED_BY))
        self.assertEqual(missing, [], f"routed but no SEEDED_BY entry: {missing}")

    def test_every_seeder_names_a_module_that_exists(self):
        for bug_class, where in SEEDED_BY.items():
            for module in (m.strip() for m in where.split(",")):
                with self.subTest(bug_class=bug_class, module=module):
                    self.assertTrue((RECON / module).is_file(),
                                    f"{bug_class} claims {module}, which is absent")

    def test_score_py_classes_match_their_seeded_by_entries(self):
        """Anything score.py emits must be recorded as seeded there, and vice versa."""
        emitted = score_classes()
        claimed = {c for c, w in SEEDED_BY.items() if w == "score.py"}
        self.assertEqual(sorted(emitted - claimed), [],
                         "score.py emits classes absent from SEEDED_BY")
        self.assertEqual(sorted(claimed - emitted), [],
                         "SEEDED_BY credits score.py with classes it does not emit")

    def test_finding_only_classes_are_never_routed_or_seeded(self):
        """These reach the graph through findings, not coverage rows."""
        for bug_class in FINDING_ONLY_CLASSES:
            with self.subTest(bug_class=bug_class):
                self.assertNotIn(bug_class, SKILLS_FOR_CLASS)
                self.assertNotIn(bug_class, SEEDED_BY)
                self.assertEqual(seeded_by(bug_class), "")

    def test_finding_only_classes_are_reachable_from_chain_hints(self):
        """If nothing chains to them they are dead labels, not a design choice."""
        in_hints = {c for row in CHAIN_HINTS for c in row[:2]}
        for bug_class in FINDING_ONLY_CLASSES:
            with self.subTest(bug_class=bug_class):
                self.assertIn(bug_class, in_hints)

    def test_known_cve_is_produced_by_vulnintel(self):
        """known-cve is finding-only because vulnintel creates the finding itself."""
        text = (RECON / "vulnintel.py").read_text(encoding="utf-8")
        self.assertIn('"known-cve"', text)

    def test_unrouted_seeded_classes_are_declared_not_accidental(self):
        """A seeded class with no skill renders '-' in coverage.md.

        That is allowed, but it should be a short and known list rather than a
        growing one. Update this set deliberately when a class is routed.
        """
        expected_unrouted = {"file-read", "open-redirect"}
        actual = set(SEEDED_BY) - set(SKILLS_FOR_CLASS)
        self.assertEqual(actual, expected_unrouted,
                         f"seeded-but-unrouted set changed: {sorted(actual)}")


class NewSkillWiringTests(unittest.TestCase):
    """hunt-xxe and hunt-graphql are skill-only, like hunt-idor: no ledger module."""

    def test_xxe_and_graphql_are_routed_and_present(self):
        for bug_class, skill in (("xxe", "hunt-xxe"), ("graphql", "hunt-graphql")):
            with self.subTest(bug_class=bug_class):
                self.assertEqual(SKILLS_FOR_CLASS[bug_class], (skill,))
                self.assertTrue(skill_path(skill).is_file())
                self.assertIn(skill, [k for k, _ in HUNT_SKILLS])

    def test_xxe_skill_separates_rung_from_channel(self):
        text = skill_path("hunt-xxe").read_text(encoding="utf-8")
        for needle in ("error-local", "in-band", "blind", "content-type-flip"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)

    def test_graphql_skill_defers_substitution_and_transport(self):
        text = skill_path("hunt-graphql").read_text(encoding="utf-8")
        self.assertIn("hunt-idor", text)
        self.assertIn("hunt-csrf", text)


if __name__ == "__main__":
    unittest.main()
