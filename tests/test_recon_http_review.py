"""HTTP/1 capture lint is deterministic defensive review, not a desync detector."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon.cli import main
from recon.http_review import HttpReview, inspect_http1
from recon.pipeline import Recon
from tests.test_recon import write_campaign


class HttpFramingTests(unittest.TestCase):
    def test_normal_request_and_unchanged_positive_control(self):
        result = inspect_http1(b"GET / HTTP/1.1\r\nHost: acme.test\r\n\r\n")
        self.assertEqual(result["verdict"], "well-formed-observation")
        self.assertFalse(result["smuggling_confirmed"])

    def test_ambiguous_length_is_rejected_not_confirmed_smuggling(self):
        for extra in (b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
                      b"Content-Length: 0\r\nContent-Length: 0\r\n",
                      b"Content-Length: -1\r\n", b"Content-Length: 0,0\r\n"):
            with self.subTest(extra=extra):
                result = inspect_http1(b"POST / HTTP/1.1\r\nHost: acme.test\r\n" + extra + b"\r\n")
                self.assertEqual(result["verdict"], "reject")
                self.assertFalse(result["smuggling_confirmed"])

    def test_whitespace_folding_and_missing_host_rejected(self):
        for raw in (b"GET / HTTP/1.1\r\nHost : acme.test\r\n\r\n",
                    b"GET / HTTP/1.1\r\n Folded: value\r\n\r\n",
                    b"GET / HTTP/1.1\r\n\r\n",
                    b"GET / HTTP/1.1\nHost: acme.test\n\n",
                    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
            with self.subTest(raw=raw):
                self.assertEqual(inspect_http1(raw)["verdict"], "reject")

    def test_body_length_and_following_messages_rejected(self):
        prefix = b"POST / HTTP/1.1\r\nHost: acme.test\r\n"
        self.assertEqual(inspect_http1(prefix + b"Content-Length: 2\r\n\r\nOK")["verdict"],
                         "well-formed-observation")
        for tail in (b"Content-Length: 1\r\n\r\nOK", b"\r\nextra"):
            self.assertEqual(inspect_http1(prefix + tail)["verdict"], "reject")

    def test_bounded_chunked_validation_and_unsupported_features(self):
        prefix = b"POST / HTTP/1.1\r\nHost: acme.test\r\nTransfer-Encoding: chunked\r\n\r\n"
        self.assertEqual(inspect_http1(prefix + b"2\r\nOK\r\n0\r\n\r\n")["verdict"],
                         "well-formed-observation")
        for tail in (b"2\r\nO", b"0\r\n\r\nextra", b"2;unsupported=x\r\nOK\r\n0\r\n\r\n"):
            self.assertEqual(inspect_http1(prefix + tail)["verdict"], "reject")
        response = inspect_http1(b"HTTP/1.1 200 OK\r\n\r\nOK", "response")
        self.assertEqual(response["verdict"], "inconclusive")

    def test_size_cap_and_no_echo_of_untrusted_values(self):
        with self.assertRaisesRegex(ValueError, "megabytes"):
            inspect_http1(b"X" * 2_000_001)
        raw = b"GET /?secret=PRIVATE_QUERY HTTP/1.1\r\nHost: acme.test\r\nCookie: PRIVATE_COOKIE\r\n\r\n"
        result = json.dumps(inspect_http1(raw))
        self.assertNotIn("PRIVATE", result)


class HttpReviewJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        camp = write_campaign(Path(self.tmp.name) / "camp", "passive", [], in_scope=["acme.test"])
        self.root = camp.root
        self.ctx = Recon(camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.review = HttpReview(self.ctx)
        (self.root / "capture.http").write_bytes(b"GET / HTTP/1.1\r\nHost: acme.test\r\n\r\n")

    def test_inspect_dedup_show_verify_cli_without_sockets(self):
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            first = self.review.inspect("capture.http", "https://acme.test/")
            again = self.review.inspect("capture.http", "https://acme.test/")
            self.assertEqual(first["id"], again["id"])
            self.assertTrue(self.review.verify()["ok"])
            with contextlib.redirect_stdout(io.StringIO()) as out:
                for action in ("status", "verify"):
                    self.assertEqual(main(["http-review", action, str(self.root)]), 0)
                self.assertEqual(main(["http-review", "show", str(self.root), "--id", str(first["id"])]), 0)
            self.assertNotIn("GET / HTTP", out.getvalue())
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        self.assertEqual(self.ctx.store.jobs(), [])

    def test_capture_target_mismatch_and_out_of_scope_are_not_attributed(self):
        result = self.review.inspect("capture.http", "https://acme.test/other")
        self.assertIn("capture-url-authority-or-target-mismatch", result["issues"])
        self.assertTrue(self.review.verify()["ok"])
        with self.assertRaisesRegex(ValueError, "scope"):
            self.review.inspect("capture.http", "https://outside.test/")

    def test_tamper_detected_and_cli_verify_exits_two(self):
        self.review.inspect("capture.http", "https://acme.test/")
        (self.root / "capture.http").write_bytes(b"changed")
        self.assertFalse(self.review.verify()["ok"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["http-review", "verify", str(self.root)]), 2)

    def test_bounds_and_schema_cannot_be_bypassed(self):
        for limit, offset in ((0, 0), (501, 0), (1, -1), (True, 0)):
            with self.assertRaises(ValueError):
                self.review.status(limit, offset)
        with self.assertRaises(ValueError):
            self.review.inspect("../outside.http", "https://acme.test/")

    def test_cli_inspect_recomputes_attribution_and_policy_staleness(self):
        with patch("socket.socket", side_effect=AssertionError("offline only")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["http-review", "inspect", str(self.root), "--file", "capture.http",
                                   "--url", "https://acme.test/"]), 0)
        rid = json.loads(out.getvalue())["id"]
        self.assertTrue(self.review.verify()["ok"])
        self.ctx.campaign.raw["rules"] = ["updated review-only rules"]
        self.assertTrue(self.review.show(rid)["integrity_issues"])
        self.assertFalse(self.review.verify()["ok"])

    def test_inspector_never_outputs_private_url_query(self):
        (self.root / "capture.http").write_bytes(
            b"GET /?secret=PRIVATE_QUERY HTTP/1.1\r\nHost: acme.test\r\nCookie: PRIVATE_COOKIE\r\n\r\n")
        result = self.review.inspect("capture.http", "https://acme.test/?secret=PRIVATE_QUERY")
        self.assertNotIn("PRIVATE", json.dumps(self.review.show(result["id"])))
        self.assertTrue(self.review.verify()["ok"])


if __name__ == "__main__":
    unittest.main()
