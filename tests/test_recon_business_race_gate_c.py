"""Gate C is a static adversarial evaluation set, NOT a model A/B run."""
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests" / "fixtures" / "recon" / "business_race_judgment.json"


class StaticJudgmentFixtures(unittest.TestCase):
    def test_static_cases_are_bounded_complete_and_have_distinct_expected_dispositions(self):
        cases = json.loads(CASES.read_text())
        self.assertEqual(len(cases), 16)
        self.assertEqual([c["id"] for c in cases], [f"C{i:02d}-" + c["id"].split("-", 1)[1]
                                                   for i, c in enumerate(cases, 1)])
        for c in cases:
            with self.subTest(case=c["id"]):
                self.assertEqual(set(c), {"id", "prompt", "expected", "owner", "must_say"})
                self.assertGreaterEqual(len(c["must_say"]), 3)
                self.assertLess(len(c["prompt"]), 500)
                self.assertTrue((ROOT / ".claude" / "skills" / c["owner"] / "SKILL.md").is_file())
                self.assertNotIn("https://posten.no", c["prompt"])

    def test_skills_explain_the_critical_hand_off_boundaries(self):
        logic = (ROOT / ".claude/skills/hunt-business-logic/SKILL.md").read_text().lower()
        race = (ROOT / ".claude/skills/hunt-race-conditions/SKILL.md").read_text().lower()
        for phrase in ("inferred-observed", "negative control", "schedule dependence",
                       "owned", "declared policy", "no real money"):
            self.assertIn(phrase, logic)
        for phrase in ("operator-run", "not a gate", "unknown", "constraint",
                       "agent-driven", "2–8", "source-qualified"):
            self.assertIn(phrase, race)
