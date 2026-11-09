"""Offline import, provenance, context and catalog regression tests; no target access."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon.catalog import catalog, render_catalog
from recon.cli import main
from recon.har import import_har
from recon.ingest import import_artifact, read_artifact
from recon.pipeline import JOB_NEEDS, Recon
from recon.report import write_reports
from tests.test_recon import write_campaign


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        campaign = write_campaign(self.root / "campaign", "passive", [],
                                  in_scope=["acme.com", "*.acme.com"])
        self.ctx = Recon(campaign, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        network = patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("offline only"))
        network.start()
        self.addCleanup(network.stop)

    def artifact(self, source, data, name=None):
        path = self.root / (name or source)
        path.write_text(data if isinstance(data, str) else json.dumps(data))
        return path

    def ingest(self, source, data):
        return import_artifact(self.ctx, self.artifact(source, data), source)

    def har(self):
        return {"log": {"entries": [{
            "request": {"url": "https://api.acme.com/orders/101?user_id=22", "method": "POST",
                        "headers": [{"name": "Cookie", "value": "DO_NOT_STORE_COOKIE"}],
                        "postData": {"mimeType": "application/json", "text": json.dumps({
                            "note": "DO_NOT_STORE_BODY", "otp": "12345678",
                            "token": "abcdef0123456789abcdef0123456789", "owner_id": 11})}},
            "response": {"status": 200, "content": {"mimeType": "application/json"}}}]}}

    def test_subfinder_text_and_json_hosts_normalize(self):
        self.assertEqual(self.ingest("subfinder", "API.ACME.COM.\napi.acme.com\n")["accepted"], 2)
        result = self.ingest("subfinder", '{"host":"api.acme.com"}\n')
        self.assertEqual(result["new_assets"], 0)
        self.assertEqual(len(self.ctx.store.assets("host")), 1)
        self.assertEqual(len(self.ctx.store.jobs()), 1)

    def test_bbot_surface_subset_never_promotes_findings(self):
        records = [{"type": "DNS_NAME", "data": "api.acme.com"},
                   {"type": "URL", "data": "https://api.acme.com/orders/101"},
                   {"type": "HTTP_RESPONSE", "data": {"url": "https://api.acme.com/orders/102"}},
                   {"type": "OPEN_TCP_PORT", "data": "api.acme.com:8443"},
                   {"type": "VULNERABILITY", "data": {"severity": "CRITICAL"}}]
        result = self.ingest("bbot", records)
        self.assertEqual((result["accepted"], result["unsupported"]), (4, 1))
        self.assertEqual(len(self.ctx.store.assets("endpoint")), 1)
        self.assertEqual(len(self.ctx.store.assets("network-service")), 1)
        self.assertFalse(self.ctx.store.facts())

    def test_httpx_keeps_imported_claims_separate(self):
        result = self.ingest("httpx", [
            {"url": "https://api.acme.com/orders", "status_code": 200, "tech": ["nginx"]}])
        self.assertEqual(result["accepted"], 1)
        attrs = self.ctx.store.assets("service")[0]["attrs"]
        self.assertEqual(attrs["reported_status"], 200)
        self.assertEqual(attrs["reported_tech"], ["nginx"])
        self.assertNotIn("live", attrs)
        self.assertNotIn("status", attrs)

    def test_katana_and_httpx_merge_asset_not_methods_or_sources(self):
        self.ingest("httpx", [{"url": "https://API.acme.com:443/orders/101?limit=10", "method": "GET"}])
        self.ingest("katana", [{"request": {"endpoint": "https://api.acme.com/orders/102?after=secret",
                                               "method": "POST"}}])
        eps = self.ctx.store.assets("endpoint")
        self.assertEqual(len(eps), 1)
        self.assertEqual(set(eps[0]["attrs"]["sources"]), {"httpx", "katana"})
        self.assertEqual({o["method"] for o in self.ctx.store.operations()}, {"GET", "POST"})
        self.assertEqual(len(self.ctx.store.variants()), 2)
        self.assertEqual(len(self.ctx.store.provenance_records()), 2)
        self.assertNotIn("secret", "\n".join(self.ctx.store.db.iterdump()))

    def test_reimport_renamed_file_does_not_inflate_assets_jobs_or_provenance(self):
        data = [{"url": "https://api.acme.com/orders/101", "method": "GET"}]
        first = self.ingest("httpx", data)
        before = (self.ctx.store.total_assets(), len(self.ctx.store.jobs()),
                  len(self.ctx.store.provenance_records()))
        second = import_artifact(self.ctx, self.artifact("httpx", data, "renamed"), "httpx")
        self.assertEqual(second["import_id"], first["import_id"])
        self.assertEqual(second["duplicate_records"], 1)
        self.assertEqual(second["new_assets"], 0)
        self.assertEqual(before, (self.ctx.store.total_assets(), len(self.ctx.store.jobs()),
                                  len(self.ctx.store.provenance_records())))

    def test_changed_content_is_new_source_record_not_new_family(self):
        self.ingest("httpx", [{"url": "https://api.acme.com/orders/101"}])
        self.ingest("httpx", [{"url": "https://api.acme.com/orders/102"}])
        self.assertEqual(len(self.ctx.store.imports()), 2)
        self.assertEqual(len(self.ctx.store.assets("endpoint")), 1)
        self.assertEqual(len(self.ctx.store.provenance_records()), 2)

    def test_scopesentry_nested_export_and_unsupported_risk(self):
        result = self.ingest("scopesentry", {"data": {"list": [
            {"subdomain": "api.acme.com"}, {"ip": "127.0.0.1", "port": 8080},
            {"url": "https://api.acme.com/orders"}, {"type": "risk", "url": "https://api.acme.com/"}]}})
        self.assertEqual((result["accepted"], result["unsupported"], result["out_of_scope"]), (3, 1, 1))

    def test_out_of_scope_never_enqueues(self):
        result = self.ingest("bbot", [{"type": "DNS_NAME", "data": "evil.example"},
                                       {"type": "URL", "data": "https://evil.example/api/x"}])
        self.assertEqual(result["out_of_scope"], 2)
        self.assertFalse(self.ctx.store.jobs())
        self.assertEqual(len(self.ctx.store.provenance_records()), 2)

    def test_malformed_jsonl_counted_without_echoing_secrets(self):
        result = self.ingest("httpx", 'DO_NOT_ECHO_SECRET\n{"url":"https://api.acme.com/ok"}\n')
        self.assertEqual((result["accepted"], result["malformed"]), (1, 1))
        self.assertNotIn("DO_NOT_ECHO_SECRET", json.dumps(result))
        self.assertEqual(self.ctx.store.imports()[0]["stats"]["malformed"], 1)

    def test_malformed_urls_and_methods_are_rejected_before_writing(self):
        for url, method in [("https://api.acme.com:bad/x", "GET"),
                            ("https://secret@api.acme.com/x", "GET"),
                            ("https://api.acme.com/x", "invented")]:
            result = self.ingest("httpx", [{"url": url, "method": method}])
            self.assertEqual(result["malformed"], 1)
        self.assertEqual(self.ctx.store.total_assets(), 0)

    def test_unknown_envelope_and_bounds_fail_before_import_registration(self):
        with self.assertRaises(ValueError):
            self.ingest("scopesentry", {"data": [], "items": []})
        with patch("recon.ingest.MAX_RECORDS", 1):
            with self.assertRaises(ValueError):
                self.ingest("subfinder", "a.acme.com\nb.acme.com\n")
        with self.assertRaises(ValueError):
            read_artifact(self.artifact("large", "0123456789"), limit=5)
        self.assertFalse(self.ctx.store.imports())

    def test_har_same_context_dedup_distinct_contexts_retained(self):
        path = self.artifact("har", self.har())
        first = import_har(self.ctx, path, "alice", "member", "a", "draft")
        second = import_har(self.ctx, path, "alice", "member", "a", "draft")
        self.assertEqual((first["duplicate_samples"], second["duplicate_samples"]), (0, 1))
        for account, role, tenant, state in [("bob", "member", "a", "draft"),
                                              ("alice", "admin", "a", "draft"),
                                              ("alice", "member", "b", "draft"),
                                              ("alice", "member", "a", "submitted")]:
            import_har(self.ctx, path, account, role, tenant, state)
        self.assertEqual(len(self.ctx.store.observations()), 5)
        self.assertEqual(len(self.ctx.store.imports()), 5)
        self.assertEqual(len(self.ctx.store.operations()), 1)
        self.assertEqual(self.ctx.store.observations()[0]["context"]["tenant"], "a")

    def test_har_does_not_copy_headers_bodies_or_sensitive_idlike_values(self):
        import_har(self.ctx, self.artifact("har", self.har()), "alice")
        dump = "\n".join(self.ctx.store.db.iterdump())
        for value in ("DO_NOT_STORE_COOKIE", "DO_NOT_STORE_BODY", "12345678",
                      "abcdef0123456789abcdef0123456789"):
            self.assertNotIn(value, dump)
        ids = self.ctx.store.observations()[0]["params"]["ids"]
        self.assertEqual(ids["owner_id"], "11")

    def test_har_malformed_record_does_not_abort_valid_record(self):
        data = self.har()
        data["log"]["entries"].insert(0, {"request": {"url": ["invalid"]}})
        stats = import_har(self.ctx, self.artifact("har", data), "alice")
        self.assertEqual((stats["malformed"], stats["endpoints"]), (1, 1))

    def test_synthetic_and_real_bases_survive_both_ingestion_orders(self):
        for first, second in [("synthetic-ui", "captured-real-traffic"),
                              ("captured-real-traffic", "synthetic-ui")]:
            self.ctx.add_endpoint("https://api.acme.com/one", "runtime", method="GET", extra={"basis": first})
            self.ctx.add_endpoint("https://api.acme.com/one", "har", method="GET", extra={"basis": second})
        op = self.ctx.store.operations()[0]
        self.assertEqual(set(op["attrs"]["bases"]), {"synthetic-ui", "captured-real-traffic"})

    def test_exact_variants_preserve_path_behavior_boundaries(self):
        for path in ("/orders/101", "/orders/102", "/orders/101/", "/Orders/101"):
            self.ctx.add_endpoint("https://api.acme.com" + path, "js", method="GET")
        self.assertEqual(len(self.ctx.store.assets("endpoint")), 2)
        self.assertEqual(len(self.ctx.store.variants()), 4)

    def test_report_separates_contexts_and_does_not_claim_confirmation(self):
        import_har(self.ctx, self.artifact("har", self.har()), "alice", "member", "a", "draft")
        self.ctx.refresh_coverage()
        paths = write_reports(self.ctx)
        text = paths[0].read_text()
        self.assertIn("Captured context coverage", text)
        self.assertIn("captured-real-traffic", text)
        self.assertIn("Exact path variants", text)
        self.assertTrue(all(c["status"] == "untested" for c in self.ctx.store.coverage()))

    def test_cli_import_and_context_flags(self):
        path = self.artifact("har", self.har())
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main(["import-har", str(self.ctx.campaign.root), str(path), "--account", "alice",
                       "--role", "admin", "--tenant", "a", "--workflow-state", "draft"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.ctx.store.observations()[0]["context"]["role"], "admin")
        bad = self.artifact("httpx", "malformed\n")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["import", str(self.ctx.campaign.root), str(bad), "--format", "httpx"]), 2)


class CatalogTests(unittest.TestCase):
    def test_inventory_matches_real_handlers_and_guides(self):
        data = catalog()
        self.assertEqual(data["execution"]["llm_agents"], 0)
        self.assertEqual(data["execution"]["job_handlers"], len(JOB_NEEDS))
        self.assertEqual(data["execution"]["scanner_import_adapters"], 5)
        root = Path(__file__).resolve().parents[1]
        for phase in data["phases"]:
            text = (root / phase["guide"]).read_text()
            self.assertIn("name: " + phase["id"], text)
            self.assertIn("description:", text)
            self.assertTrue(set(phase["handlers"]).issubset(JOB_NEEDS))
        self.assertEqual(len(data["phases"]), 7)
        self.assertIn("manual-only", render_catalog(data))

    def test_catalog_cli_needs_no_campaign_or_network(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["catalog", "--json"]), 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["execution"]["automatically_invoked_llm_skills"], 0)

    def test_all_repository_fixtures_offline_end_to_end(self):
        fixtures = Path(__file__).parent / "fixtures" / "recon"
        with tempfile.TemporaryDirectory() as directory:
            campaign = write_campaign(Path(directory), "passive", [],
                                      in_scope=["example.com", "*.example.com"])
            ctx = Recon(campaign, log=lambda _: None)
            try:
                with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("offline")):
                    for source, name in [("subfinder", "subfinder.txt"), ("bbot", "bbot.jsonl"),
                                         ("httpx", "httpx.jsonl"), ("katana", "katana.jsonl"),
                                         ("scopesentry", "scopesentry.json")]:
                        result = import_artifact(ctx, fixtures / name, source)
                        self.assertEqual(result["malformed"], 0, source)
                    for account in ("alice", "bob", "alice"):
                        import_har(ctx, fixtures / f"{account}.har", account, "member", account, "draft")
                    ctx.refresh_coverage()
                    write_reports(ctx)
                self.assertEqual(ctx.store.request_count(), 0)
                self.assertEqual(len(ctx.store.assets("endpoint")), 1)
                self.assertEqual(len(ctx.store.observations()), 2)
                self.assertEqual(len(ctx.store.imports()), 7)
                self.assertEqual({o["method"] for o in ctx.store.operations()}, {"GET", "POST", "UNKNOWN"})
                self.assertTrue((Path(directory) / "recon.md").exists())
            finally:
                ctx.store.close()


if __name__ == "__main__":
    unittest.main()
