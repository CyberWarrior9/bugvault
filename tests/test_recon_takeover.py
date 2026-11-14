"""Deeper subdomain-takeover detection: provider CNAMEs, dig gaps, chain context."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.active import job_probe
from recon.fingerprint import takeover_match, takeover_providers_for_cname
from recon.pipeline import Recon
from tests.test_recon import write_campaign


class ProviderMatchingTests(unittest.TestCase):
    def test_cname_provider_matching(self):
        cases = {
            "app.example.herokuapp.com": ["heroku"],
            "docs.example.github.io": ["github-pages"],
            "assets.foo.cloudfront.net": ["cloudfront"],
            "shop.example.myshopify.com": ["shopify"],
            "staging.example.azurewebsites.net": ["azure"],
            "blog.example.wordpress.com": ["wordpress-com"],
            "random.example.invalid": [],
            "": [],
            "herokuapp.com.evil.net": [],  # suffix must be a domain boundary, not substring
        }
        for cname, expected in cases.items():
            with self.subTest(cname=cname):
                self.assertEqual(takeover_providers_for_cname(cname), expected)

    def test_expanded_body_signatures(self):
        bodies = {
            "pantheon": "The gods are wise, but do not know of the site which you seek.",
            "squarespace": "<html><body>DOMAIN NOT FOUND</body></html>",
            "cloudfront": "Bad request. We can't connect to the server for this app or website.",
            "vercel": "DEPLOYMENT_NOT_FOUND: The deployment could not be found",
            "aws-s3": "<Error><Code>NoSuchBucket</Code></Error>",
            "aws-s3-alt": "The specified bucket does not exist",
        }
        expected = {"pantheon": "pantheon", "squarespace": "squarespace",
                    "cloudfront": "cloudfront", "vercel": "vercel",
                    "aws-s3": "aws-s3", "aws-s3-alt": "aws-s3"}
        for label, body in bodies.items():
            with self.subTest(label=label):
                self.assertIn(expected[label], takeover_match(body))
        self.assertNotIn("heroku", takeover_match("just a normal page"))

    def test_matching_is_substring_based_by_design(self):
        # Signatures are substring matches (standard for takeover scanners): prose that
        # quotes an exact signature string can false-positive. That is why takeover
        # signals are stored as `inferred` leads requiring verification, never facts.
        self.assertIn("aws-s3", takeover_match("we discuss how NoSuchBucket errors happen"))
        self.assertEqual(takeover_match("a perfectly ordinary page about clouds"), [])


class ProbeTakeoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.camp = write_campaign(self.root / "camp", "active", [],
                                   in_scope=["acme.test", "*.acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)

    def _host_asset(self, host):
        aid = self.ctx.add("host", host, source="test")
        return self.ctx.store.get_asset(aid)

    def _facts(self, kind):
        return self.ctx.store.db.execute(
            "SELECT summary FROM facts WHERE kind=?", (kind,)).fetchall()

    def test_dangling_cname_names_the_provider(self):
        asset = self._host_asset("dead.acme.test")
        with patch("recon.active.resolve_ips", return_value=[]), \
             patch("recon.active.dig_cname", return_value="dead-acme.herokuapp.com"):
            job_probe(self.ctx, asset)
        leads = [f["summary"] for f in self._facts("takeover-lead")]
        self.assertTrue(any("heroku" in s for s in leads), leads)

    def test_dangling_cname_unknown_provider_still_recorded(self):
        asset = self._host_asset("odd.acme.test")
        with patch("recon.active.resolve_ips", return_value=[]), \
             patch("recon.active.dig_cname", return_value="something.internal.corp"):
            job_probe(self.ctx, asset)
        self.assertTrue(self._facts("takeover-lead"))

    def test_missing_dig_records_a_collection_gap(self):
        asset = self._host_asset("quiet.acme.test")
        with patch("recon.active.resolve_ips", return_value=[]), \
             patch("recon.active.dig_cname", return_value=None), \
             patch("recon.active.shutil.which", return_value=None):
            job_probe(self.ctx, asset)
        gaps = [f["summary"] for f in self._facts("collection-gap")]
        self.assertTrue(any("dig unavailable" in s for s in gaps), gaps)
        self.assertFalse(self._facts("takeover-lead"))

    def test_cookie_domain_becomes_impact_context_on_takeover(self):
        # an earlier response from the parent domain set a wildcard-parent cookie
        self.ctx.store.record_request(
            "GET", "https://app.acme.test/", 200, "fixture", [],
            {"set-cookie": "session=abc; Domain=.acme.test; HttpOnly"},
            b"<html>ok</html>", basis="target-http")
        asset = self._host_asset("dead.acme.test")
        with patch("recon.active.resolve_ips", return_value=[]), \
             patch("recon.active.dig_cname", return_value="dead-acme.herokuapp.com"):
            job_probe(self.ctx, asset)
        context = [f["summary"] for f in self._facts("takeover-impact-context")]
        self.assertTrue(any("cookie domain spans *.acme.test" in s for s in context), context)

    def test_no_impact_context_without_wildcard_cookies(self):
        self.ctx.store.record_request(
            "GET", "https://app.acme.test/", 200, "fixture", [],
            {"set-cookie": "session=abc; Path=/"},  # host-only cookie
            b"<html>ok</html>", basis="target-http")
        asset = self._host_asset("dead.acme.test")
        with patch("recon.active.resolve_ips", return_value=[]), \
             patch("recon.active.dig_cname", return_value="dead-acme.herokuapp.com"):
            job_probe(self.ctx, asset)
        self.assertFalse(self._facts("takeover-impact-context"))


if __name__ == "__main__":
    unittest.main()
