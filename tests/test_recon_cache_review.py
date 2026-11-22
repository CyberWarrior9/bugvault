"""Offline capture fidelity, privacy, profiles and isolation; no remote traffic."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon.cache_review import CacheReview
from recon.cli import main
from recon.pipeline import Recon
from recon.report import write_reports
from tests.test_recon import write_campaign


class CacheReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        camp = write_campaign(Path(self.tmp.name) / "camp", "passive", [], in_scope=["acme.test"])
        self.root = camp.root
        self.ctx = Recon(camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.review = CacheReview(self.ctx)

    def put(self, name, value):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        (self.root / name).write_bytes(data)
        return name

    def har(self, url="https://acme.test/account?secret=PRIVATE_QUERY", body="PRIVATE_BODY"):
        return {"log": {"entries": [{
            "request": {"method": "GET", "url": url, "headers": [
                {"name": "Cookie", "value": "session=PRIVATE_COOKIE"}]},
            "response": {"status": 200, "headers": [
                {"name": "Set-Cookie", "value": "one=PRIVATE_COOKIE"},
                {"name": "Set-Cookie", "value": "two=PRIVATE_COOKIE"},
                {"name": "Cache-Control", "value": "private, no-store"}],
                "content": {"text": body, "size": len(body.encode())}}}]}}

    def capture(self):
        self.put("capture.har", self.har())
        return self.review.import_file("capture.har", "har", account="owned-v")["captures"][0]

    def profile(self, capture=None, **identity):
        capture = capture or self.capture()
        self.put("owner-log.txt", b"owned rule observation, no cache entry asserted")
        declaration = {"schema": 1, "capture": capture,
                       "identity": {"behavior": "account", "policy_revision": "r1",
                                    "path_class": "account", "representation": "html",
                                    "authority_context": "owned-v", "layer": "unknown",
                                    "pop": "unknown", **identity},
                       "observations": {"keying": "unknown", "forwarding": "unknown",
                                        "store": "unknown", "serve": "unknown", "ttl_seconds": None},
                       "evidence": "owner-log.txt"}
        self.put("profile.json", declaration)
        return self.review.profile("profile.json")["id"]

    def test_har_privacy_duplicate_headers_and_no_network(self):
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            record = self.capture()
            shown = self.review.show(record)
            self.assertTrue(self.review.verify()["ok"])
        text = json.dumps(shown)
        for secret in ("PRIVATE_QUERY", "PRIVATE_BODY", "PRIVATE_COOKIE"):
            self.assertNotIn(secret, text)
        self.assertEqual(shown["fidelity"], "har-normalized")
        self.assertTrue(shown["body_complete"])
        self.assertEqual(shown["signals"]["duplicate_response_headers"], 1)
        self.assertTrue(shown["signals"]["no_store_directive"])
        self.assertEqual(shown["signals"]["store"], "unknown")
        self.assertEqual(self.ctx.store.jobs(), [])
        self.assertEqual(self.ctx.store.network_attempts(), 0)

    def test_dedupe_keeps_contexts_separate(self):
        record = self.capture()
        again = self.review.import_file("capture.har", "har", account="owned-v")
        other = self.review.import_file("capture.har", "har", account="owned-a")
        self.assertEqual(again["captures"], [record])
        self.assertNotEqual(other["captures"], [record])

    def test_incomplete_har_body_stays_incomplete(self):
        har = self.har()
        har["log"]["entries"][0]["response"]["content"]["size"] = 1000
        self.put("truncated.har", har)
        rid = self.review.import_file("truncated.har", "har")["captures"][0]
        self.assertFalse(self.review.show(rid)["body_complete"])

    def test_base64_har_and_missing_body(self):
        har = self.har(body="normal")
        content = har["log"]["entries"][0]["response"]["content"]
        content.update(text=base64.b64encode(b"normal").decode(), encoding="base64")
        self.put("base64.har", har)
        rid = self.review.import_file("base64.har", "har")["captures"][0]
        self.assertTrue(self.review.show(rid)["body_complete"])
        del content["text"]
        self.put("missing.har", har)
        rid = self.review.import_file("missing.har", "har")["captures"][0]
        self.assertFalse(self.review.show(rid)["body_complete"])

    def test_raw_pair_and_burp_formats_preserve_raw_fidelity(self):
        request = b"GET /account HTTP/1.1\r\nHost: acme.test\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: a\r\nX-Test: b\r\n\r\nOK"
        self.put("req.http", request)
        self.put("resp.http", response)
        self.put("pair.json", {"schema": 1, "url": "https://acme.test/account",
                               "request": "req.http", "response": "resp.http"})
        rid = self.review.import_file("pair.json", "raw-pair")["captures"][0]
        self.assertEqual(self.review.show(rid)["fidelity"], "raw-http1")
        self.assertTrue(self.review.show(rid)["body_complete"])
        self.put("burp.json", [{"url": "https://acme.test/account", "method": "GET", "status": 200,
                               "request": request.decode(), "response": response.decode()}])
        self.assertTrue(self.review.import_file("burp.json", "burp-json")["captures"])
        xml = ('<items><item><url>https://acme.test/account</url>'
               '<request base64="true">' + base64.b64encode(request).decode() + '</request>'
               '<response base64="true">' + base64.b64encode(response).decode() + '</response>'
               '</item></items>').encode()
        self.put("burp.xml", xml)
        self.assertTrue(self.review.import_file("burp.xml", "burp-xml")["captures"])

    def test_out_of_scope_batch_is_rejected_without_partial_rows(self):
        har = self.har()
        extra = self.har(url="https://outside.test/account")["log"]["entries"][0]
        har["log"]["entries"].append(extra)
        self.put("outside.har", har)
        with self.assertRaisesRegex(ValueError, "scope"):
            self.review.import_file("outside.har", "har")
        self.assertEqual(self.review.status()["total"], 0)

    def test_import_refuses_symlinks_escapes_and_entities(self):
        self.put("capture.har", self.har())
        (self.root / "link.har").symlink_to(self.root / "capture.har")
        for name in ("link.har", "../capture.har", str(self.root / "capture.har")):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.review.import_file(name, "har")
        self.put("entity.xml", b'<!DOCTYPE items [<!ENTITY x "text">]><items/>')
        with self.assertRaisesRegex(ValueError, "entities"):
            self.review.import_file("entity.xml", "burp-xml")

    def test_profiles_are_behavior_and_capture_scoped(self):
        capture = self.capture()
        first = self.profile(capture, behavior="account")
        second = self.profile(capture, behavior="public")
        self.assertNotEqual(first, second)
        self.assertEqual(self.review.show(first)["identity"]["layer"], "unknown")
        self.assertTrue(self.review.show(first)["semantic_review_required"])
        self.assertIsNone(self.review.show(first)["observations"]["ttl_seconds"])

    def test_isolation_requires_distinct_evidence_and_never_grants_traffic(self):
        profile = self.profile()
        self.put("partition.txt", b"owner partition observation")
        self.put("control.txt", b"independent clean control")
        declaration = {"schema": 1, "profile": profile, "purpose": "isolated-observation",
                       "state": "source-supported", "viewer": "owned-a",
                       "artifacts": {"partition": "partition.txt"}}
        self.put("isolation.json", declaration)
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.review.isolation("isolation.json")
        declaration["artifacts"]["control"] = "control.txt"
        self.put("isolation.json", declaration)
        result = self.review.isolation("isolation.json")
        self.assertFalse(result["traffic_authorized"])
        self.assertTrue(self.review.verify()["ok"])

    def test_source_tamper_and_retained_copy_tamper_detected(self):
        record = self.capture()
        _, data = self.review.journal.get(record)
        source = self.root / data["artifacts"]["source"]["path"]
        original = source.read_bytes()
        self.assertEqual(source.stat().st_mode & 0o777, 0o600)
        self.put("capture.har", self.har(body="changed"))
        self.assertFalse(self.review.verify()["ok"])
        self.assertEqual(source.read_bytes(), original)
        source.write_bytes(b"tampered")
        self.assertFalse(self.review.verify()["ok"])

    def test_pages_cli_and_report_are_offline(self):
        record = self.capture()
        self.profile(record)
        first = self.review.status(limit=1)
        self.assertTrue(first["truncated"])
        self.assertEqual(first["next_offset"], 1)
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(["cache", "reviews", str(self.root), "--limit", "1"]), 0)
                self.assertEqual(main(["cache", "verify-reviews", str(self.root)]), 0)
            reports = write_reports(self.ctx)
        self.assertNotIn("PRIVATE_BODY", out.getvalue())
        coverage = next(p for p in reports if p.name == "coverage.md").read_text()
        self.assertIn("Cache capture and isolation reviews", coverage)
        self.assertNotIn("PRIVATE_COOKIE", coverage)

    def test_descendants_flag_invalid_capture_dependencies(self):
        profile = self.profile()
        self.put("receipt.json", {"schema": 1, "profile": profile, "state": "unknown",
                                  "purpose": "control/readback", "viewer": "owned-a", "artifacts": {}})
        isolation = self.review.isolation("receipt.json")["id"]
        self.put("capture.har", self.har(body="later edit"))
        self.assertTrue(self.review.show(isolation)["integrity_issues"])
        self.assertFalse(self.review.verify()["ok"])
        with self.assertRaisesRegex(ValueError, "stale or invalid"):
            self.review.isolation("receipt.json")

    def test_malformed_har_and_entry_cap_fail_before_rows(self):
        for value in ({"log": []}, {"log": {"entries": [None]}},
                      {"log": {"entries": [{"request": [], "response": {}}]}}):
            self.put("bad.har", value)
            with self.assertRaises(ValueError):
                self.review.import_file("bad.har", "har")
        entry = self.har()["log"]["entries"][0]
        self.put("many.har", {"log": {"entries": [entry] * 501}})
        with self.assertRaisesRegex(ValueError, "500"):
            self.review.import_file("many.har", "har")
        self.assertEqual(self.review.status()["total"], 0)

    def test_raw_pair_tracks_source_edits_and_attribution(self):
        self.put("req.http", b"GET /different HTTP/1.1\r\nHost: acme.test\r\n\r\n")
        self.put("resp.http", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        self.put("pair.json", {"schema": 1, "url": "https://acme.test/account",
                               "request": "req.http", "response": "resp.http"})
        rid = self.review.import_file("pair.json", "raw-pair")["captures"][0]
        self.assertEqual(self.review.show(rid)["request_analysis"]["verdict"], "reject")
        self.put("req.http", b"changed")
        self.assertFalse(self.review.verify()["ok"])

    def test_new_import_cli_and_integrity_exit(self):
        self.put("capture.har", self.har())
        with patch("socket.socket", side_effect=AssertionError("offline only")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            rc = main(["cache", "import", str(self.root), "--file", "capture.har",
                       "--format", "har", "--account", "owned-v"])
        self.assertEqual(rc, 0)
        rid = json.loads(out.getvalue())["captures"][0]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["cache", "review", str(self.root), "--id", str(rid)]), 0)
        self.put("capture.har", self.har(body="edit"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["cache", "verify-reviews", str(self.root)]), 2)


if __name__ == "__main__":
    unittest.main()
