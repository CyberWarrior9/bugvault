"""Input census: locations, sensitive flags, probe receipts, coverage join, CLI."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.cli import main
from recon.inputs import input_census
from recon.pipeline import Recon
from recon.score import applicable_classes
from recon.skillmap import skill_path, skills_for
from tests.test_recon import write_campaign


class InputCensusFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)

    def census(self):
        return input_census(self.ctx, self.aid)


class InputCensusTests(InputCensusFixture):
    def test_locations_accounts_and_sensitive_flags_merge(self):
        self.aid = self.ctx.add_endpoint(
            "https://acme.test/profile", "har", method="POST",
            params=["firstName", "lastName", "username", "bio", "apiKey", "userId"],
            extra={"id_params": ["userId"]})
        self.ctx.store.add_observation(
            self.aid, "POST", "alice", {"query": ["username"], "body":
                                        ["firstName", "lastName", "bio", "apiKey"], "ids": {"userId": "314"},
                                        "auth": True},
            200, "har", capture_key="har:1:0", context={"basis": "captured-real-traffic"})
        self.ctx.store.add_observation(
            self.aid, "POST", "bob", {"query": ["username"], "body":
                                      ["firstName", "lastName", "bio", "apiKey"], "ids": {"userId": "271"},
                                      "auth": True},
            200, "har", capture_key="har:2:0", context={"basis": "captured-real-traffic"})
        data = self.census()
        self.assertEqual(data["input_count"], 6)
        by_name = {i["name"]: i for i in data["inputs"]}
        self.assertEqual(by_name["username"]["locations"], ["query"])
        self.assertEqual(by_name["firstName"]["locations"], ["body"])
        self.assertEqual(by_name["userId"]["id_like"], True)
        self.assertEqual(by_name["userId"]["locations"], ["query/body (ID-like value stored)"])
        self.assertTrue(by_name["apiKey"]["sensitive_name"])
        self.assertFalse(by_name["bio"]["sensitive_name"])
        self.assertEqual(by_name["username"]["seen_by_accounts"], ["alice", "bob"])
        self.assertFalse(data["executed"])

    def test_probe_receipts_from_stored_requests_and_bodies(self):
        self.aid = self.ctx.add_endpoint(
            "https://acme.test/search", "har", method="POST", params=["q", "filter"])
        body = b'{"q": "canary_probe", "filter": "x"}'
        import hashlib
        sha = hashlib.sha256(body).hexdigest()
        (self.camp.bodies_dir).mkdir(parents=True, exist_ok=True)
        (self.camp.bodies_dir / sha).write_bytes(body)
        cur = self.ctx.store.db.execute(
            "INSERT INTO requests(ts, method, url, status, purpose) VALUES(?,?,?,?,?)",
            ("t", "POST", "https://acme.test/search?ignored=1", 200, "test"))
        rid = cur.lastrowid
        self.ctx.store.db.execute(
            "INSERT INTO request_payload(request_id, body_sha256, body_len, content_type)"
            " VALUES(?,?,?,?)", (rid, sha, len(body), "application/json"))
        self.ctx.store.db.commit()
        data = self.census()
        by_name = {i["name"]: i for i in data["inputs"]}
        self.assertEqual(by_name["q"]["probe_seen_in_requests"], [rid])
        self.assertEqual(by_name["filter"]["probe_seen_in_requests"], [rid])
        self.assertEqual(by_name["q"]["tested"], True)
        self.assertIn("probe_seen means the name appeared", data["basis"])

    def test_coverage_join_and_known_gaps(self):
        self.aid = self.ctx.add_endpoint("https://acme.test/search", "har",
                                         method="GET", params=["q"])
        self.ctx.refresh_coverage()
        self.assertIn("xss", applicable_classes({"value": "https://acme.test/search", "attrs": {"params": ["q"]}}))
        data = self.census()
        self.assertIn("xss", data["untested_hint"])
        self.assertTrue(any("header and cookie" in gap for gap in data["known_gaps"]))
        self.assertTrue(any("hidden parameters" in gap for gap in data["known_gaps"]))
        self.ctx.store.set_coverage(self.aid, "xss", "tested", "context mapped")
        self.assertEqual(self.census()["coverage"]["xss"], "tested")

    def test_non_endpoint_or_bad_ids_are_refused(self):
        service = self.ctx.add("service", "https://acme.test", source="html")
        for bad in (service, 0, -1, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                input_census(self.ctx, bad)

    def test_cli_is_offline(self):
        self.aid = self.ctx.add_endpoint("https://acme.test/search", "har",
                                         method="GET", params=["q"])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                patch("socket.socket", side_effect=AssertionError("CLI must remain offline")):
            rc = main(["inputs", str(self.root), "--asset-id", str(self.aid)])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue())["input_count"], 1)


class XSSSQLiSkillPolicyTests(unittest.TestCase):
    def setUp(self):
        self.texts = {skill: skill_path(skill).read_text()
                      for skill in ("hunt-xss", "hunt-sqli")}

    def test_census_context_mapping_and_probe_ladder_are_explicit(self):
        for skill, text in self.texts.items():
            with self.subTest(skill=skill):
                haystack = text.replace("-", " ").lower()
                for needle in ("recon inputs", "field ledger", "probe", "marker",
                               "canary", "dedicated browser through Burp",
                               "Hard limits", "negative control", "three-attempt"):
                    self.assertIn(needle.lower().replace("-", " "), haystack)
        for needle in ("reflected", "stored", "DOM", "blind", "HTML injection",
                       "attribute", "JS string", "WAF"):
            self.assertIn(needle.lower().replace("-", " "), self.texts["hunt-xss"].replace("-", " ").lower())
        for needle in ("error-based", "boolean", "time-based", "out-of-band",
                       "UNION", "second-order", "differential", "destructive"):
            self.assertIn(needle.lower().replace("-", " "), self.texts["hunt-sqli"].replace("-", " ").lower())

    def test_chains_use_supported_relations_and_inputs_command_exists(self):
        from recon.findings import RELATIONS
        import re
        for skill, text in self.texts.items():
            for relation in re.findall(r"`(yields-[a-z]+|escalates-via|enables|spawns|pivots-to)`", text):
                self.assertIn(relation, RELATIONS)
            self.assertIn("fact check", text)
        self.assertEqual(skills_for("xss"), ("hunt-xss",))
        self.assertEqual(skills_for("sqli"), ("hunt-sqli",))


if __name__ == "__main__":
    unittest.main()
