"""WAF profiles: block-signature classification (incl. silent-strip), element
table per host/location/content-type, bounded probe plan. All offline."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.fields import FieldLedger
from recon.pipeline import Recon
from recon.waf import (MAX_ELEMENTS_PER_HOST, OUTCOMES, WAFProfiles, classify,
                       classify_with_headers, template_sha)
from tests.test_recon import write_campaign


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.baseline = b"<html><body>saved: 7</body></html>"
        self.baseline_status = 200

    def test_status_block(self):
        result = classify(self.baseline_status, self.baseline, 403, b"denied", "<", "m1")
        self.assertEqual(result["kind"], "status")
        self.assertIn("403", result["notes"])

    def test_template_challenge(self):
        body = (b"<html>Attention Required! Cloudflare challenge captcha request blocked"
                b"</html>")
        result = classify(self.baseline_status, self.baseline, 403, body, "<", "m1")
        self.assertEqual(result["kind"], "template")
        self.assertIn("cloudflare", result["markers_hit"])

    def test_allowed_and_silent_strip(self):
        passed = b"<html><body>saved: 7 <b>m1</b></body></html>"
        self.assertEqual(classify(self.baseline_status, self.baseline, 200, passed,
                                  "<b>", "m1")["kind"], "allowed")
        stripped = b"<html><body>saved: 7</body></html>"
        result = classify(self.baseline_status, self.baseline, 200, stripped, "<b>", "m1")
        self.assertEqual(result["kind"], "stripped")
        self.assertIn("silent strip", result["notes"])

    def test_reset_and_modified(self):
        self.assertEqual(classify(None, self.baseline, None, b"", "<", "m1",
                                  reset=True)["kind"], "reset")
        other = b"<html><body>saved: 8 different</body></html>"
        result = classify(self.baseline_status, self.baseline, 200, other, "<b>", "m1")
        self.assertEqual(result["kind"], "modified")

    def test_header_promotion(self):
        other = b"<html><body>saved: 8 different</body></html>"
        signature = classify(self.baseline_status, self.baseline, 200, other, "<b>", "m1")
        promoted = classify_with_headers(
            {"cf-ray": "1", "server": "x"}, {"server": "x"}, signature)
        self.assertEqual(promoted["kind"], "header")
        self.assertIn("cf-ray", promoted["added_headers"])
        # a blocked signature is never promoted to header kind
        blocked = classify(self.baseline_status, self.baseline, 403, b"denied", "<", "m1")
        self.assertEqual(classify_with_headers({"cf-ray": "1"}, {}, blocked)["kind"],
                         "status")

    def test_template_hash_normalizes_ids_and_digits(self):
        a = template_sha(b"user 314 session abcdef1234567890abcdef1234567890")
        b = template_sha(b"user 271 session ffffffffffffffffffffffffffffffff")
        self.assertEqual(a, b)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.waf = WAFProfiles(self.ctx)

    def test_observe_classifies_and_records(self):
        result = self.waf.observe("acme.test", 200, b"<html>saved 7</html>", 403,
                                  b"Attention Required captcha blocked", "<", "m1")
        self.assertEqual(result["signature"]["kind"], "template")
        profile = self.waf.show("acme.test")
        self.assertEqual(profile["signature"]["kind"], "template")
        self.assertEqual(profile["outcomes"][0]["outcome"], "blocked")
        self.assertEqual(profile["blocked_elements"], ["<"])

    def test_record_outcomes_per_location(self):
        self.waf.record("acme.test", "'", "char", outcome="allowed", location="form")
        self.waf.record("acme.test", "'", "char", outcome="blocked", location="json")
        profile = self.waf.show("acme.test")
        outcomes = {(o["element"], o["location"]): o["outcome"]
                    for o in profile["outcomes"]}
        self.assertEqual(outcomes[("'", "form")], "allowed")
        self.assertEqual(outcomes[("'", "json")], "blocked")
        self.assertEqual(profile["surviving_chars"], ["'"])
        self.assertEqual(profile["blocked_elements"], ["'"])  # blocked anywhere blocks
        with self.assertRaises(ValueError):
            self.waf.record("acme.test", "<", outcome="bypassed")
        with self.assertRaises(ValueError):
            self.waf.record("acme.test", "<", outcome="allowed", location="graphql")

    def test_plan_is_bounded_single_then_pair_and_skips_recorded(self):
        plan = self.waf.plan("acme.test")
        self.assertLessEqual(len(plan["probes"]), 60)
        singles = [p for p in plan["probes"] if p["step"] == "single"]
        pairs = [p for p in plan["probes"] if p["step"] == "pair"]
        self.assertTrue(singles)
        self.assertTrue(pairs)
        markers = {p["marker"] for p in plan["probes"]}
        self.assertEqual(len(markers), len(plan["probes"]))  # unique per probe
        self.assertIn("dedicated browser", plan["how"])
        self.assertFalse(plan["executed"])
        # recording a single removes it from the plan; tag pairs with the same
        # leading element remain
        self.waf.record("acme.test", "<", "char", outcome="blocked", location="query")
        plan2 = self.waf.plan("acme.test")
        self.assertFalse(any(p["step"] == "single" and p["element"] == "<"
                             for p in plan2["probes"]))
        self.assertTrue(any(p["element"] == "<b><" and p["step"] == "pair"
                            for p in plan2["probes"]))

    def test_element_cap(self):
        for i in range(MAX_ELEMENTS_PER_HOST):
            self.waf.record("acme.test", f"elem{i}", "char", outcome="allowed")
        with self.assertRaises(ValueError):
            self.waf.record("acme.test", "one-too-many", "char", outcome="allowed")

    def test_show_unknown_host(self):
        with self.assertRaises(ValueError):
            self.waf.show("nobody.test")

    def test_packet_reads_waf_profile(self):
        aid = self.ctx.add_endpoint("https://acme.test/profile", "har", method="POST",
                                    params=["bio"], extra={"id_params": []})
        self.ctx.store.add_observation(aid, "POST", "alice",
                                       {"body": ["bio"], "query": [], "ids": {}},
                                       200, "har", capture_key="h:1:0",
                                       context={"basis": "captured-real-traffic"})
        ledger = FieldLedger(self.ctx)
        ledger.sync(aid)
        marker = ledger.canary(aid, "bio")["marker"]
        resp = b"<div>" + marker.encode() + b"</div>"
        self.ctx.store.record_request("POST", "https://acme.test/profile", 200, "t",
                                      [], {"Content-Type": "text/html"}, body=resp,
                                      body_complete=True, basis="t")
        (self.camp.bodies_dir).mkdir(parents=True, exist_ok=True)
        ledger.trace(marker)
        ledger.fingerprint(aid, "db", "mysql")
        ledger.fingerprint(aid, "csp", "default-src 'self'")
        self.waf.record("acme.test", "'", "char", outcome="allowed")
        self.waf.record("acme.test", "<script>", "tag", outcome="blocked")
        packet = ledger.packet(aid, "bio", "xss-stored")
        self.assertIn("'", packet["surviving_chars"])
        self.assertIn("<script>", packet["blocked_elements"])
        self.assertTrue(packet["waf_ref"].startswith("acme.test@"))


if __name__ == "__main__":
    unittest.main()
