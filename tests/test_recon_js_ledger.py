"""Offline build/packet/asset-graph checks; no target requests or test accounts."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from recon import active, extract
from recon.campaign import Campaign, ConfigError
from recon.cli import main
from recon.jsgraph import importmap_urls, precache_urls
from recon.jsledger import JsLedger
from recon.pipeline import Recon
from recon.har import import_har
from recon.report import write_reports
from recon.net import BudgetExceeded
from tests.test_recon import write_campaign


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [], in_scope=["a.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)

    def script(self, build, body, *, url=None, basis="owned-fixture", context=None):
        return self.ctx.store.record_request(
            "GET", url or f"https://a.test/_next/static/{build}/main.js", 200,
            "owned-fixture", [], {}, body=body.encode(), body_complete=True,
            basis=basis, context=context or {})

    def test_append_only_builds_stale_sets_and_synthetic_not_captured(self):
        self.script("B1", 'fetch("/api/old",{method:"GET"});')
        led = JsLedger(self.ctx)
        led.sync()
        self.script("B2", 'fetch("/api/current",{method:"GET"});')
        self.ctx.add_endpoint("https://a.test/api/current", "runtime", method="GET")
        eid = self.ctx.store.find_asset("endpoint", "https://a.test/api/current")["id"]
        self.ctx.store.add_observation(eid, "GET", "test-a", {}, 200, "runtime")
        self.assertEqual(led.sync()["builds"], 2)
        sets = led.diff("https://a.test")["sets"]
        self.assertEqual(sets["zombie"], ["GET https://a.test/api/old"])
        self.assertEqual(sets["js_only"], ["GET https://a.test/api/current"])
        self.assertEqual(led.sync()["build_artifacts_added"], 0)
        plan = led.plan(packets=True)
        self.assertEqual([p["lane"] for p in plan["leads"][:2]], ["zombie", "js_only"])
        self.assertEqual(plan["leads"][0]["packet"]["state"], "blocked")
        self.assertFalse(led.status()["complete"])
        self.assertEqual(led.verify()["ok"], True)
        cfg = json.loads((self.root / "scope.json").read_text())
        cfg["js"] = {"stale": {"max_builds": 2, "max_old_assets": 0}}
        (self.root / "scope.json").write_text(json.dumps(cfg))
        smaller = JsLedger(Recon(Campaign.load(self.root), store=self.ctx.store, log=lambda _: None))
        self.assertEqual(len(smaller.builds()["builds"]), 2)

    def test_precache_importmap_and_traffic_gap_reconciliation(self):
        self.assertEqual(extract.parse_page('<script type="importmap">{"imports":{"app":"/static/app.js"}}</script>').inline_scripts, [])
        urls, gaps = importmap_urls('{"imports":{"app":"/static/app.js"}}',
                                    "https://a.test/", ['import("app")'])
        self.assertEqual(urls, ["https://a.test/static/app.js"])
        self.assertEqual(gaps, [])
        urls, clipped = precache_urls('self.__WB_MANIFEST=[{url:"/static/only.js",revision:"1"}]',
                                      "https://a.test/sw.js")
        self.assertEqual(urls, ["https://a.test/static/only.js"])
        self.assertFalse(clipped)
        self.assertEqual(precache_urls(
            'precacheAndRoute(self.__WB_MANIFEST);const other=["/static/not-cached.js"]',
            "https://a.test/sw.js"), ([], True))
        invalid, gaps = importmap_urls('{"imports":{"bad":"http://[invalid/path.js"}}',
                                        "https://a.test/", [])
        self.assertEqual(invalid, [])
        self.assertIn("unparseable import-map URL", gaps)
        self.ctx.store.upsert_asset("js", "https://a.test/_next/static/B1/traffic.js",
                                    in_scope=True, attrs={"sources": ["burp"]})
        self.script("B1", 'navigator.serviceWorker.register("/sw.js")')
        self.script("B1", 'self.__WB_MANIFEST=[{url:"/static/only.js",revision:"1"}]',
                    url="https://a.test/sw.js")
        led = JsLedger(self.ctx)
        led.sync()
        graph = led.status()["graphs"]["https://a.test"]
        self.assertEqual(graph["precache_only"], 1)
        self.assertEqual(len(graph["traffic_only"]), 1)
        self.assertNotEqual(next(e["state"] for e in led.status()["stages"] if
                                 e["stage"] == "js-inventory"), "complete")
        self.ctx.store.record_request("GET", "https://a.test/index.html", 200, "fixture", [], {},
                                      body=b'<html><script src="/_next/static/B1/traffic.js"></script></html>',
                                      body_complete=True, basis="owned-fixture")
        led.sync()
        self.assertEqual(len(led.status()["graphs"]["https://a.test"]["traffic_only"]), 1)
        self.script("B1", 'fetch("/api/traffic")',
                    url="https://a.test/_next/static/B1/traffic.js")
        led.sync()
        self.assertEqual(led.status()["graphs"]["https://a.test"]["traffic_only"], [])

    def test_rungs_must_bind_to_response_and_no_direct_confirmation(self):
        self.script("B1", 'fetch("/api/old",{method:"GET"})')
        self.script("B2", 'fetch("/api/new",{method:"GET"})')
        led = JsLedger(self.ctx)
        led.sync()
        lead = next(x for x in led.plan()["leads"] if x["lane"] == "zombie")
        wrong = self.ctx.store.record_request("GET", "https://a.test/api/other", 200,
                                               "fixture", [], {}, body=b"{}", body_complete=True)
        with self.assertRaisesRegex(ValueError, "not this operation"):
            led.record(lead["lead_key"], rung="removed-op", outcome="200", response_id=wrong)
        rid = self.ctx.store.record_request("GET", "https://a.test/api/old", 200,
                                             "fixture", [], {}, body=b"{}", body_complete=True)
        self.assertEqual(led.record(lead["lead_key"], rung="removed-op", outcome="200",
                                    response_id=rid)["state"], "live-observed")
        with self.assertRaises(ValueError):
            led.record(lead["lead_key"], state="confirmed")
        with self.assertRaises(ValueError):
            led.record(lead["lead_key"], rung="version-sibling", outcome="404")
        self.assertFalse(led.status()["complete"])
        self.ctx.store.db.execute("UPDATE requests SET status=403 WHERE id=?", (rid,))
        self.ctx.store.db.commit()
        self.assertFalse(led.verify()["ok"])

    def test_retired_asset_queue_is_opt_in_and_scope_bounded(self):
        self.script("B1", 'fetch("/api/old",{method:"GET"})')
        self.script("B2", 'fetch("/api/new",{method:"GET"})')
        cfg = json.loads((self.root / "scope.json").read_text())
        for bad in ({"max_builds": 1}, {"max_old_assets": 1}, {"max_old_assets": 1001}):
            (self.root / "scope.json").write_text(json.dumps({**cfg, "js": {"stale": bad}}))
            with self.assertRaises(ConfigError):
                Campaign.load(self.root)
        cfg["js"] = {"rules_reviewed": "2026-11-15", "stale": {"max_old_assets": 1}}
        cfg["program_url"] = "https://program.example.test/rules"
        (self.root / "scope.json").write_text(json.dumps(cfg))
        approved = Recon(Campaign.load(self.root), store=self.ctx.store, log=lambda _: None)
        led = JsLedger(approved)
        calls = Mock()
        approved.client.get = calls
        led.sync()
        jobs = [j for j in approved.store.jobs() if j["kind"] == "jsretained"]
        self.assertEqual(len(jobs), 1)
        calls.assert_not_called()  # sync only queued; run is a separate explicit action
        self.assertIn("/B1/", approved.store.get_asset(jobs[0]["asset_id"])["value"])

    def test_pair_secret_redaction_and_cli_export(self):
        secret = "sb_secret_" + "S" * 30
        self.script("B1", 'fetch("/api/admin",{method:"GET"});const k="' + secret + '"')
        led = JsLedger(self.ctx)
        led.sync()
        self.assertIn("public-by-design", __import__("recon.jsintel", fromlist=["secret_class"]).secret_class(
            "supabase-publishable", "sb_publishable_" + "P" * 30))
        low = self.ctx.store.record_request("GET", "https://a.test/_next/static/B1/main.js", 403,
                                            "fixture", [], {}, body=b"deny", body_complete=True,
                                            context={"account": "low"})
        owner = self.ctx.store.record_request("GET", "https://a.test/_next/static/B1/main.js", 200,
                                              "fixture", [], {}, body=b"source", body_complete=True,
                                              context={"account": "owner"})
        self.assertEqual(led.asset_pair(low, owner)["outcome"], "denied")
        output = self.root / "packets.json"
        led.export("packets", output)
        self.assertNotIn(secret, output.read_text())
        self.assertNotIn(secret, (self.root / ".recon/recon.db").read_text(errors="replace"))
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(["js", "status", str(self.root)]), 0)
        self.assertIn('"complete": false', stdout.getvalue())
        self.assertNotIn(secret, stdout.getvalue())

    def test_har_body_opt_in_does_not_enqueue_authenticated_refetch(self):
        body = 'fetch("/api/private",{method:"GET"})'
        har = {"log": {"entries": [{"request": {
            "url": "https://a.test/_next/static/B1/private.js", "method": "GET", "headers": []},
            "response": {"status": 200, "content": {
                "mimeType": "application/javascript", "size": len(body), "text": body}}}]}}
        p = self.root / "test.har"
        p.write_text(json.dumps(har))
        self.assertEqual(import_har(self.ctx, p, "owned-a", "member")["script_bodies"], 0)
        self.assertFalse(any(j["kind"] == "jsparse" for j in self.ctx.store.jobs()))
        self.assertEqual(import_har(self.ctx, p, "owned-a", "member", script_bodies=True)[
            "script_bodies"], 1)
        self.assertTrue(JsLedger(self.ctx).sync()["added"])
        self.assertFalse(any(j["kind"] == "jsparse" for j in self.ctx.store.jobs()))

    def test_active_graph_only_queues_scoped_refs_no_target_requests(self):
        svc_id = self.ctx.add("service", "https://a.test", source="fixture")
        page = Mock(text=lambda: '<html><script type="importmap">'
                    '{"imports":{"admin":"/static/admin.js",'
                    '"outside":"https://outside.test/remote.js"}}'
                    '</script><script>import("admin");navigator.serviceWorker.register("/sw.js")'
                    '</script></html>', headers={}, set_cookie=[], status=200,
                    blocked_redirect="")
        self.ctx.client.get = Mock()
        active._harvest_page(self.ctx, self.ctx.store.get_asset(svc_id), page, "https://a.test/")
        assets = [a["value"] for a in self.ctx.store.assets("js")]
        self.assertIn("https://a.test/static/admin.js", assets)
        self.assertIn("https://a.test/sw.js", assets)
        self.assertNotIn("https://outside.test/remote.js", assets)
        self.ctx.client.get.assert_not_called()

    def test_cli_lineage_report_and_coarse_guard(self):
        self.script("B1", 'fetch("/api/retired",{method:"GET"})')
        led = JsLedger(self.ctx)
        led.sync()
        lead = led.plan(family="J01")["leads"][0]["lead_key"]
        service = self.ctx.store.find_asset("service", "https://a.test")
        self.assertEqual(next(c["status"] for c in self.ctx.store.coverage() if
                              c["bug_class"] == "js-bundle" and
                              c["asset_id"] == service["id"]), "untested")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["cov", str(self.root), str(service["id"]),
                                   "js-bundle", "tested", "--note", "coarse"]), 1)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["finding", "add", str(self.root), "--title", "Review retired API",
                                   "--class", "access-control", "--url", "https://a.test/api/retired",
                                   "--lineage", lead]), 0)
        self.assertEqual(led.show(lead)["lead"]["downstream"][0]["stage"], "lead")
        eid = self.ctx.add_endpoint("https://a.test/api/retired", "fixture", method="GET")
        self.ctx.store.seed_coverage(eid, {"access-control": "static reference; server policy untested"})
        ref = f"cov:{eid}:access-control"
        led.record(lead, state="handed-off", ref=ref)
        self.assertEqual(led.plan()["leads"][0]["destination"],
                         {"ref": ref, "status": "untested", "owner": "coverage"})
        self.ctx.store.set_coverage(eid, "access-control", "tested", "owned fixture")
        self.assertEqual(led.show(lead)["lead"]["destination"]["status"], "tested")
        write_reports(self.ctx)
        report = (self.root / "recon.md").read_text()
        cov = (self.root / "coverage.md").read_text()
        self.assertIn("JS intelligence", report)
        self.assertIn("Retained builds", report)
        self.assertIn("JS bundle coverage", cov)
        self.assertIn("hunt-js-bundle", cov)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["js", "show", str(self.root), lead]), 0)
        self.assertIn('"stage": "lead"', output.getvalue())

    def test_unkeyed_chunk_link_and_incomplete_asset_keep_stages_open(self):
        self.script("B1", 'navigator.serviceWorker.register("/static/child.js")')
        self.script("unused", 'fetch("/api/child",{method:"GET"})',
                    url="https://a.test/static/child.js")
        self.script("B2", 'fetch("/api/current",{method:"GET"})')
        led = JsLedger(self.ctx)
        led.sync()
        sets = led.diff("https://a.test")["sets"]
        self.assertIn("GET https://a.test/api/child", sets["zombie"])
        self.assertEqual(led.status()["graphs"]["https://a.test"]["unlinked_build_assets"], 0)
        self.ctx.store.record_request("GET", "https://a.test/partial.js", 200, "fixture", [], {},
                                      body=b'fetch("/api/partial")', body_complete=False)
        led.sync()
        self.assertIn("https://a.test/partial.js",
                      led.status()["graphs"]["https://a.test"]["incomplete"])
        self.assertFalse(led.status()["complete"])

    def test_retained_stop_cap_recheck_and_review_resume(self):
        self.script("B1", 'fetch("/api/old",{method:"GET"})')
        self.script("B2", 'fetch("/api/new",{method:"GET"})')
        cfg = json.loads((self.root / "scope.json").read_text())
        cfg["program_url"] = "https://program.example.test/rules"
        cfg["js"] = {"rules_reviewed": "2026-11-15", "stale": {"max_old_assets": 1}}
        (self.root / "scope.json").write_text(json.dumps(cfg))
        approved = Recon(Campaign.load(self.root), store=self.ctx.store, log=lambda _: None)
        led = JsLedger(approved)
        led.sync()
        old = next(j for j in approved.store.jobs() if j["kind"] == "jsretained")
        asset = approved.store.get_asset(old["asset_id"])
        approved.client.get = Mock(return_value=Mock(status=429, truncated=False))
        with self.assertRaises(BudgetExceeded):
            active.job_jsretained(approved, asset)
        approved.client.get.assert_called_once()
        with self.assertRaises(BudgetExceeded):
            active.job_jsretained(approved, asset)
        approved.client.get.assert_called_once()
        with self.assertRaises(ValueError):
            led.resume_retained("https://a.test", "")
        self.assertTrue(led.resume_retained("https://a.test", "Program rule and host reviewed")[
            "review_recorded"])
        approved.client.get = Mock(return_value=Mock(status=404, truncated=False))
        active.job_jsretained(approved, asset)
        approved.client.get.assert_called_once()
        self.assertEqual(led.builds()["builds"][0]["retired_assets"], 0)

    def test_truncated_map_is_gap_not_invalid_json_or_disclosure(self):
        self.ctx.store.record_request("GET", "https://a.test/app.js.map", 200, "fixture", [], {},
                                      body=b'{"version":3,"sources":["private.ts"',
                                      body_complete=False)
        led = JsLedger(self.ctx)
        led.sync()
        facts = self.ctx.store.facts()
        self.assertTrue(any("truncated" in f["summary"] for f in facts))
        self.assertFalse(any("not valid JSON" in f["summary"] for f in facts))
        self.assertFalse(any(c["bug_class"] == "info-disclosure" for c in
                             self.ctx.store.coverage()))
        self.assertFalse(led.status()["complete"])

    def test_j17_pair_needs_complete_evidence_and_detects_body_corruption(self):
        self.script("B1", 'fetch("/api/admin")')
        led = JsLedger(self.ctx)
        led.sync()
        url = "https://a.test/_next/static/B1/main.js"
        low = self.ctx.store.record_request("GET", url, 200, "fixture", [], {},
                                            body=b"visible", body_complete=True,
                                            context={"account": "low"})
        owner = self.ctx.store.record_request("GET", url, 200, "fixture", [], {},
                                              body=b"private", body_complete=True,
                                              context={"account": "owner"})
        self.assertEqual(led.asset_pair(low, owner)["outcome"], "served")
        lead = next(x for x in led.plan(family="J17", packets=True)["leads"] if
                    x["family"] == "J17")
        self.assertIn("non-public", lead["packet"]["ceiling"])
        digest = self.ctx.store.response(low)["body_sha256"]
        (self.camp.bodies_dir / digest).write_bytes(b"tampered")
        self.assertFalse(led.verify()["ok"])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["js", "verify", str(self.root)]), 2)
        self.assertIn('"ok": false', output.getvalue())

    def test_three_builds_horizon_retains_history_and_offline_commands(self):
        self.script("B1", 'fetch("/api/v1/old",{method:"GET"})')
        self.script("B2", 'fetch("/api/v2/middle",{method:"GET"})')
        self.script("B3", 'fetch("/api/v3/current",{method:"GET"})')
        led = JsLedger(self.ctx)
        with patch("socket.socket.connect", side_effect=AssertionError("offline JS opened socket")):
            led.sync()
            self.assertEqual(len(led.builds()["builds"]), 3)
            self.assertEqual(led.diff("https://a.test")["removed"],
                             ["GET https://a.test/api/v2/middle"])
            self.assertTrue(led.plan()["leads"])
            self.assertTrue(led.verify()["ok"])
            led.export("stale", self.root / "stale.json")
        cfg = json.loads((self.root / "scope.json").read_text())
        cfg["js"] = {"stale": {"max_builds": 2, "max_old_assets": 0}}
        (self.root / "scope.json").write_text(json.dumps(cfg))
        smaller = JsLedger(Recon(Campaign.load(self.root), store=self.ctx.store, log=lambda _: None))
        self.assertEqual(len(smaller.builds()["builds"]), 3)
        self.assertEqual(smaller.diff("https://a.test")["sets"]["earlier"],
                         ["GET https://a.test/api/v2/middle"])
        self.assertEqual(smaller.builds()["builds"][0]["in_horizon"], False)

    def test_unknown_static_method_is_not_absent_from_matching_real_capture(self):
        self.script("B1", 'fetch("/api/owned")')
        eid = self.ctx.add_endpoint("https://a.test/api/owned", "har", method="GET")
        self.ctx.store.add_observation(eid, "GET", "owned-a", {}, 200, "har")
        led = JsLedger(self.ctx)
        led.sync()
        sets = led.status()["sets"]["https://a.test"]
        self.assertIn("UNKNOWN https://a.test/api/owned", sets["current"])
        self.assertEqual(sets["js_only"], [])


if __name__ == "__main__":
    unittest.main()
