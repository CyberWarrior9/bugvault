"""Misconfiguration class routes only as a candidate and preserves per-field boundaries."""
import unittest

from recon.score import applicable_classes
from recon.skillmap import SKILLS_FOR_CLASS, seeded_by, skill_path
from recon.findings import CHAIN_HINTS


class SecurityMisconfigurationTests(unittest.TestCase):
    def test_auth_and_config_are_candidate_rows(self):
        for path in ("/signup", "/password/reset", "/debug", "/.env"):
            with self.subTest(path=path):
                classes = applicable_classes({"value": "https://example.test" + path, "attrs": {}})
                self.assertIn("security-misconfiguration", classes)
                self.assertIn("review", classes["security-misconfiguration"])
        unrelated = applicable_classes({"value": "https://example.test/about", "attrs": {}})
        self.assertNotIn("security-misconfiguration", unrelated)
        flagged = applicable_classes({"value": "https://example.test/about",
                                      "attrs": {"security_review": True}})
        self.assertIn("security-misconfiguration", flagged)

    def test_skill_wiring_and_distinct_handoffs(self):
        self.assertEqual(SKILLS_FOR_CLASS["security-misconfiguration"],
                         ("hunt-security-misconfig",))
        self.assertEqual(seeded_by("security-misconfiguration"), "score.py")
        text = skill_path("hunt-security-misconfig").read_text().lower()
        for word in ("single-digit", "back-button", "httponly", "ntlm", "asp.net",
                     "clickjacking", "first name", "last name", "reset-with-token"):
            self.assertIn(word, text)
        self.assertTrue({"ato", "csrf", "info-disclosure"} <= {
            b for a, b, _ in CHAIN_HINTS if a == "security-misconfiguration"})


if __name__ == "__main__":
    unittest.main()
