"""Typed response predicates: prove the stated observation, not arbitrary prose."""
import contextlib
import html
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote

from recon.campaign import PolicyViolation, Scope
from recon.cli import main
from recon.factcheck import ResponseFacts
from recon.pipeline import Recon
from recon.recall import recall
from recon.report import write_reports
from tests.test_recon import LabServer, write_campaign


class FactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.camp = write_campaign(self.root / "campaign", "passive", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.checker = ResponseFacts(self.ctx)
        self.network = patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("checks must be offline"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def response(self, body=b"<html>ordinary response</html>", *, status=200, headers=None,
                 complete=True, error=None, url="https://acme.test/search"):
        return self.ctx.store.record_request("GET", url, status, "fixture", [],
                                             headers or {"Content-Type": "text/html"}, body,
                                             error=error, body_complete=complete, basis="owned-fixture")

    def marker(self, request, value="<BV_CANARY_123>"):
        return self.checker.add(request, {"type": "body_contains_raw", "marker": value})

    def test_status_is_compared_not_just_linked(self):
        request = self.response(status=403)
        result = self.checker.add(request, {"type": "status_is", "expected": 200})
        self.assertEqual(result["outcome"], "contradicted")
        self.assertEqual(result["detail"]["actual_status"], 403)
        supported = self.checker.add(request, {"type": "status_is", "expected": 403})
        self.assertEqual(supported["outcome"], "supported")

    def test_header_names_ignore_case_but_values_are_exact(self):
        request = self.response(headers={"X-Canary": "Present"})
        self.assertEqual(self.checker.add(request, {"type": "header_present", "name": "x-CANARY"})["outcome"], "supported")
        self.assertEqual(self.checker.add(request, {"type": "header_present", "name": "missing"})["outcome"], "contradicted")
        self.assertEqual(self.checker.add(request, {"type": "header_equals", "name": "X-Canary", "expected": "Present"})["outcome"], "supported")
        self.assertEqual(self.checker.add(request, {"type": "header_equals", "name": "X-Canary", "expected": "present"})["outcome"], "contradicted")

    def test_empty_header_value_is_still_present(self):
        request = self.response(headers={"X-Canary": ""})
        self.assertEqual(self.checker.add(request, {"type": "header_present", "name": "X-Canary"})["outcome"], "supported")

    def test_exact_marker_found_with_a_byte_offset(self):
        request = self.response(b"prefix <BV_CANARY_123> suffix")
        result = self.marker(request)
        self.assertEqual(result["outcome"], "supported")
        self.assertEqual(result["detail"]["byte_offset"], 7)
        self.assertNotIn("XSS", result["claim"])
        self.assertNotIn("<BV_CANARY_123>", result["claim"])  # no raw snippet in human report

    def test_encoded_marker_never_passes_the_raw_predicate(self):
        marker = "<BV_CANARY_123>"
        for encoded in (html.escape(marker), quote(marker, safe=""), r"\u003cBV_CANARY_123\u003e"):
            result = self.marker(self.response(encoded.encode()), marker)
            self.assertEqual(result["outcome"], "contradicted", encoded)

    def test_marker_in_headers_does_not_count_as_a_body_match(self):
        request = self.response(headers={"X-Canary": "<BV_CANARY_123>"})
        self.assertEqual(self.marker(request)["outcome"], "contradicted")

    def test_missing_marker_in_partial_or_legacy_body_is_inconclusive(self):
        for complete in (False, None):
            result = self.marker(self.response(b"partial response", complete=complete))
            self.assertEqual(result["outcome"], "inconclusive")

    def test_positive_match_in_a_truncated_prefix_is_a_narrow_supported_fact(self):
        result = self.marker(self.response(b"<BV_CANARY_123>", complete=False))
        self.assertEqual(result["outcome"], "supported")

    def test_empty_response_can_contradict_only_when_complete(self):
        self.assertEqual(self.marker(self.response(b"", complete=True))["outcome"], "contradicted")
        self.assertEqual(self.marker(self.response(b"", complete=False))["outcome"], "inconclusive")

    def test_missing_or_modified_body_cannot_support_a_marker(self):
        request = self.response(b"<BV_CANARY_123>")
        result = self.marker(request)
        source = self.ctx.store.bodies_dir / self.ctx.store.response(request)["body_sha256"]
        source.write_bytes(b"changed body")
        changed = self.checker.verify(result["fact_id"])
        self.assertEqual((changed["outcome"], changed["reason"]), ("inconclusive", "body_integrity_failed"))
        source.unlink()
        self.assertEqual(self.checker.verify(result["fact_id"])["reason"], "body_unavailable")

    def test_response_metadata_change_marks_the_fact_stale(self):
        request = self.response(status=200)
        result = self.checker.add(request, {"type": "status_is", "expected": 200})
        self.ctx.store.db.execute("UPDATE requests SET status=403 WHERE id=?", (request,))
        self.ctx.store.db.commit()
        self.assertEqual(self.checker.verify(result["fact_id"])["outcome"], "stale")

    def test_corrupt_response_record_is_inconclusive_instead_of_trusted(self):
        request = self.response()
        result = self.checker.add(request, {"type": "status_is", "expected": 200})
        self.ctx.store.db.execute("UPDATE requests SET resp_headers='invalid JSON' WHERE id=?", (request,))
        self.ctx.store.db.commit()
        self.assertEqual(self.checker.verify(result["fact_id"])["outcome"], "inconclusive")

    def test_context_export_requires_every_predicate_to_be_supported(self):
        request = self.response(status=200)
        good = self.checker.add(request, {"type": "status_is", "expected": 200})
        bad = self.checker.add(request, {"type": "header_present", "name": "missing"})
        with self.assertRaises(ValueError):
            self.checker.require_supported([good["fact_id"], bad["fact_id"]])
        bundle = self.checker.require_supported([good["fact_id"]])
        self.assertEqual(bundle["response_facts"][0]["outcome"], "supported")
        self.ctx.store.db.execute("UPDATE requests SET status=403 WHERE id=?", (request,))
        self.ctx.store.db.commit()
        with self.assertRaises(ValueError):
            self.checker.require_supported([good["fact_id"]])

    def test_context_export_checks_body_again_instead_of_reusing_a_pass(self):
        request = self.response(b"<BV_CANARY_123>")
        fact = self.marker(request)
        path = self.ctx.store.bodies_dir / self.ctx.store.response(request)["body_sha256"]
        path.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.checker.require_supported([fact["fact_id"]])

    def test_compression_is_not_silently_decoded_or_interpreted(self):
        request = self.response(b"<BV_CANARY_123>", headers={"Content-Encoding": "gzip"})
        self.assertEqual(self.marker(request)["reason"], "content_encoding_not_supported")

    def test_verification_body_limit_is_fail_closed(self):
        request = self.response(b"x" * 30)
        with patch("recon.factcheck.MAX_BODY_BYTES", 10):
            self.assertEqual(self.marker(request)["outcome"], "inconclusive")

    def test_transport_failure_is_not_an_http_status_fact(self):
        request = self.response(b"", status=None, error="timeout")
        result = self.checker.add(request, {"type": "status_is", "expected": 200})
        self.assertEqual((result["outcome"], result["reason"]), ("inconclusive", "no_usable_http_response"))

    def test_arbitrary_claims_code_and_bad_predicates_are_rejected(self):
        request = self.response()
        bad = [{"type": "status_is", "expected": "200"}, {"type": "status_is", "expected": True},
               {"type": "status_is", "expected": 200, "claim": "confirmed XSS"},
               {"type": "header_present", "name": "X-Test\nBad"},
               {"type": "body_regex", "pattern": ".*"},
               {"type": "body_contains_raw", "marker": ""},
               {"type": "body_contains_raw", "marker": "x" * 1025}]
        for predicate in bad:
            with self.assertRaises(ValueError):
                self.checker.add(request, predicate)
        self.assertFalse(self.checker.recent())

    def test_scope_and_asset_binding_are_checked(self):
        request = self.response()
        unrelated = self.ctx.add_endpoint("https://acme.test/invoices", "html", method="GET")
        with self.assertRaises(ValueError):
            self.checker.add(request, {"type": "status_is", "expected": 200}, unrelated)
        with self.assertRaises(PolicyViolation):
            self.marker(self.response(url="https://outside.invalid/search"))

    def test_scope_revision_can_invalidate_a_previous_fact(self):
        result = self.marker(self.response(b"<BV_CANARY_123>"))
        self.camp.scope = Scope.from_lists(["acme.test"], ["/search"])
        self.assertEqual(self.checker.verify(result["fact_id"])["outcome"], "stale")

    def test_rechecking_deduplicates_definitions_but_retains_verification_events(self):
        request = self.response()
        first = self.checker.add(request, {"type": "status_is", "expected": 200})
        second = self.checker.add(request, {"type": "status_is", "expected": 200})
        self.assertEqual(first["fact_id"], second["fact_id"])
        self.assertNotEqual(first["verification_id"], second["verification_id"])
        self.assertEqual(self.ctx.store.db.execute("SELECT count(*) FROM response_facts").fetchone()[0], 1)
        self.assertEqual(self.ctx.store.db.execute("SELECT count(*) FROM fact_verifications").fetchone()[0], 2)

    def test_legacy_metadata_can_support_status_but_not_unobserved_body_completeness(self):
        request = self.response(b"legacy captured prefix")
        self.ctx.store.db.execute("DELETE FROM response_capture WHERE request_id=?", (request,))
        self.ctx.store.db.commit()
        result = self.checker.add(request, {"type": "status_is", "expected": 200})
        self.assertEqual(result["outcome"], "supported")
        self.assertEqual(result["capture_basis"], "legacy-unattributed")
        self.assertEqual(self.marker(request)["outcome"], "inconclusive")

    def test_reports_and_recall_keep_narrative_and_checked_facts_separate(self):
        aid = self.ctx.add_endpoint("https://acme.test/search", "html", method="GET")
        self.ctx.store.add_fact(aid, "search is allegedly vulnerable", "observed")
        request = self.response()
        self.checker.add(request, {"type": "status_is", "expected": 200}, aid)
        result = recall(self.ctx, "search")
        self.assertEqual(next(h for h in result["matches"] if h["ref"].startswith("fact:"))["verification"], "not_machine_checked")
        self.assertEqual(next(h for h in result["matches"] if h["ref"].startswith("response-fact:"))["verification"], "supported")
        text = write_reports(self.ctx)[0].read_text()
        self.assertIn("Response-backed predicate checks", text)
        self.assertFalse(self.ctx.store.db.execute("SELECT 1 FROM findings WHERE stage='confirmed'").fetchone())

    def test_cli_is_offline_and_returns_nonzero_when_the_predicate_is_not_supported(self):
        request = self.response(status=403)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["responses", str(self.camp.root)]), 0)
        self.assertEqual(json.loads(out.getvalue())[0]["id"], request)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["fact", "check", str(self.camp.root), "--response", str(request),
                                   "--predicate", '{"type":"status_is","expected":200}']), 2)
            self.assertEqual(main(["fact", "list", str(self.camp.root)]), 0)


class NetworkCaptureTests(unittest.TestCase):
    def test_native_capture_exposes_response_id_and_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "site").mkdir()
            (root / "site" / "index.html").write_text("prefix <BV_CANARY_123> ending")
            with LabServer(root / "site") as lab:
                base = f"http://127.0.0.1:{lab.port}"
                camp = write_campaign(root / "campaign", "active", [], in_scope=[base])
                ctx = Recon(camp, log=lambda _: None)
                try:
                    reply = ctx.client.get(base + "/", "fixture", max_bytes=6)
                    self.assertIsInstance(reply.request_id, int)
                    self.assertEqual(ctx.store.response(reply.request_id)["body_complete"], 0)
                    result = ResponseFacts(ctx).add(reply.request_id, {"type": "body_contains_raw", "marker": "<BV_CANARY_123>"})
                    self.assertEqual(result["outcome"], "inconclusive")
                    reply = ctx.client.get(base + "/", "fixture")
                    result = ResponseFacts(ctx).add(reply.request_id, {"type": "body_contains_raw", "marker": "<BV_CANARY_123>"})
                    self.assertEqual(result["outcome"], "supported")
                    self.assertEqual(result["capture_basis"], "target-http")
                finally:
                    ctx.store.close()


if __name__ == "__main__":
    unittest.main()
