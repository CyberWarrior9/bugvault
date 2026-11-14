"""Review regressions, pinned egress and bounded provider recovery. No external network."""
import http.client
import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from recon.brief import ROLES, render
from recon.egress import ConnectionGuard, EgressViolation, _connection
from recon.findings import Findings, StageError
from recon.net import BudgetExceeded, FetchError
from recon.pipeline import Recon
from recon.reliability import ProviderError, SourceRunner
from recon.vulnintel import Sighting, kev_for, lookup, searchsploit, title_covers
from recon.planning import review, snapshot
from recon.campaign import PolicyViolation, Scope
from recon.har import import_har
from recon.recall import recall
from recon.report import context_comparisons, context_param_matrix
from tests.test_recon import LabServer, write_campaign


class ReviewBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.camp = write_campaign(self.root / "campaign", "active", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)


class BriefAndFindingTests(ReviewBase):
    def test_every_brief_has_bounded_preauthorization_and_lookup_caveats(self):
        for role in ROLES:
            text = render(self.camp, role)
            self.assertIn("pre-authorized", text)
            self.assertIn("Do not ask for permission again", text)
            self.assertIn("do not launch agents or sandbox their shells", text)
            self.assertIn("SearchSploit", text)
            self.assertNotIn("{{", text)
        self.assertIn("recon lookup", render(self.camp, "hunter"))
        self.assertIn("positive", render(self.camp, "validator"))

    def test_finding_requires_a_scope_anchor(self):
        with self.assertRaises(StageError):
            Findings(self.ctx).add("unanchored", "xss")

    def test_killing_one_lead_does_not_refute_another_confirmed_finding(self):
        fx = Findings(self.ctx)
        aid = self.ctx.add_endpoint("https://acme.test/orders/1", "har", method="GET")
        first, _ = fx.add("first", "idor-bola", asset_id=aid)
        second, _ = fx.add("second", "idor-bola", asset_id=aid)
        replay, control = self.root / "replay", self.root / "control"
        replay.write_text("assertion: unauthorized account received foreign order")
        control.write_text("assertion: patched endpoint rejects foreign order")
        fx.move(first, "confirmed", replay=replay, control=control)
        fx.move(second, "killed", note="different hypothesis refuted")
        self.assertEqual(self.ctx.store.coverage()[0]["status"], "confirmed")

    def test_scope_changes_block_further_validation(self):
        fx = Findings(self.ctx)
        fid, _ = fx.add("first", "xss", url="https://acme.test/orders")
        self.camp.scope = Scope.from_lists(["acme.test"], ["/orders"])
        with self.assertRaises(StageError):
            fx.move(fid, "confirmed")

    def test_kev_membership_never_overrides_a_version_mismatch(self):
        sighting = Sighting("https://acme.test", "apache-httpd", "2.4.50", ["fixture banner"])
        wrong = {"source": "exploit-db", "id": "EDB-fixture", "title": "Apache HTTP Server 2.4.49 - RCE",
                 "type": "webapps", "cves": ["CVE-2021-41773"]}
        with patch("recon.vulnintel.collect_sightings", return_value=[sighting]), \
             patch("recon.vulnintel.load_kev", return_value=[{
                 "cveID": "CVE-2021-41773", "vendorProject": "Apache", "product": "HTTP Server"}]), \
             patch("recon.vulnintel.searchsploit", return_value=[wrong]):
            lookup(self.ctx, use_sploitus=False, searchsploit_bin="fixture", log=lambda _: None)
        leads = Findings(self.ctx).all()
        self.assertEqual(len(leads), 1)  # product-level KEV lead is still explicitly unverified
        self.assertFalse(leads[0]["detail"]["exploits"])

    def test_lookup_keeps_a_narrow_scope_sighting_location(self):
        self.camp.scope = Scope.from_lists(["https://acme.test/allowed"], [])
        sighting = Sighting("https://acme.test", "nginx", "1.18.0", ["fixture"],
                            ["https://acme.test/allowed/index.html"])
        with patch("recon.vulnintel.collect_sightings", return_value=[sighting]), \
             patch("recon.vulnintel.load_kev", return_value=[{
                 "cveID": "CVE-2026-12345", "vendorProject": "nginx", "product": "nginx"}]):
            lookup(self.ctx, use_searchsploit=False, use_sploitus=False, log=lambda _: None)
        self.assertEqual(Findings(self.ctx).all()[0]["url"], "https://acme.test/allowed/index.html")

    def test_bad_searchsploit_output_is_failure_not_clean_no_match(self):
        process = MagicMock(returncode=0, stdout="not json")
        with patch("recon.vulnintel.subprocess.run", return_value=process):
            with self.assertRaises(ProviderError):
                searchsploit("nginx 1.18.0", "fixture")

    def test_version_suffix_and_kev_product_boundaries(self):
        self.assertIsNone(title_covers("OpenSSL 1.1.1k - fixture", "1.1.1l"))
        self.assertEqual(title_covers("OpenSSL < 1.1.1l - fixture", "1.1.1k"), "range")
        self.assertFalse(kev_for("php", [{"vendorProject": "phpMyAdmin", "product": "phpMyAdmin"}]))


class EgressTests(ReviewBase):
    def infos(self, *ips, port=443):
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM,
                 socket.IPPROTO_TCP, "", (ip, port, 0, 0) if ":" in ip else (ip, port)) for ip in ips]

    def test_private_dns_and_mixed_answers_are_rejected_before_connect(self):
        for ips in [("127.0.0.1",), ("8.8.8.8", "10.0.0.1"), ("::ffff:127.0.0.1",)]:
            with patch("recon.egress.socket.getaddrinfo", return_value=self.infos(*ips)), \
                 patch("recon.egress.socket.socket") as sock:
                with self.assertRaises(EgressViolation):
                    ConnectionGuard(self.camp, self.ctx.store).connect(("acme.test", 443), 1)
                sock.assert_not_called()

    def test_include_paths_are_case_sensitive_but_exclusions_are_conservative(self):
        scope = Scope.from_lists(["https://acme.test/Private"], ["/Private/Logout"])
        self.assertTrue(scope.is_in("https://acme.test/Private/orders"))
        self.assertFalse(scope.is_in("https://acme.test/private/orders"))
        self.assertFalse(scope.is_in("https://acme.test/Private/LOGOUT"))

    def test_denied_ip_and_scope_cidr_override_allowance(self):
        self.camp.policy.allowed_ip_ranges = ["10.0.0.0/8"]
        self.camp.policy.denied_ip_ranges = ["10.1.0.0/16"]
        with patch("recon.egress.socket.getaddrinfo", return_value=self.infos("10.1.2.3")):
            with self.assertRaises(EgressViolation):
                ConnectionGuard(self.camp, self.ctx.store).connect(("acme.test", 443), 1)
        self.camp.scope = Scope.from_lists(["acme.test"], ["8.8.8.0/24"])
        with patch("recon.egress.socket.getaddrinfo", return_value=self.infos("8.8.8.8")):
            with self.assertRaises(EgressViolation):
                ConnectionGuard(self.camp, self.ctx.store).connect(("acme.test", 443), 1)

    def test_numeric_pinning_uses_one_resolution_and_checks_peer(self):
        sock = MagicMock()
        sock.getpeername.return_value = ("8.8.8.8", 443)
        with patch("recon.egress.socket.getaddrinfo", return_value=self.infos("8.8.8.8")) as dns, \
             patch("recon.egress.socket.socket", return_value=sock):
            result = ConnectionGuard(self.camp, self.ctx.store).connect(("acme.test", 443), 1)
        dns.assert_called_once()
        sock.connect.assert_called_once_with(("8.8.8.8", 443))
        self.assertIs(result, sock)
        self.assertEqual(self.ctx.store.db.execute("SELECT peer FROM connection_events").fetchone()[0], "8.8.8.8")

    def test_unexpected_connected_peer_fails_closed(self):
        sock = MagicMock()
        sock.getpeername.return_value = ("127.0.0.1", 443)
        with patch("recon.egress.socket.getaddrinfo", return_value=self.infos("8.8.8.8")), \
             patch("recon.egress.socket.socket", return_value=sock):
            with self.assertRaises(EgressViolation):
                ConnectionGuard(self.camp, self.ctx.store).connect(("acme.test", 443), 1)
        sock.close.assert_called()

    def test_tls_keeps_original_hostname_for_sni_and_verification(self):
        guard, context = MagicMock(), MagicMock(spec=ssl.SSLContext)
        context.verify_mode, context.check_hostname = ssl.CERT_REQUIRED, True
        conn = _connection(http.client.HTTPSConnection, guard, "acme.test:443", context=context)
        conn.connect()
        self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], "acme.test")
        guard.connect.assert_called_once()

    def test_explicit_lab_address_works_and_campaign_budget_survives_new_instances(self):
        site = self.root / "site"
        site.mkdir()
        (site / "index.html").write_text("owned loopback fixture")
        with LabServer(site) as lab:
            base = f"http://127.0.0.1:{lab.port}"
            camp = write_campaign(self.root / "bounded", "active", [], in_scope=[base])
            camp.policy.max_campaign_requests = 1
            first = Recon(camp, log=lambda _: None)
            first.client.get(base + "/", "fixture")
            first.store.close()
            second = Recon(camp, log=lambda _: None)
            try:
                with self.assertRaises(BudgetExceeded):
                    second.client.get(base + "/", "fixture")
                self.assertEqual(len(lab.hits), 1)
            finally:
                second.store.close()

    def test_proxy_and_host_override_fail_without_transport(self):
        with patch.object(self.ctx.client.opener, "open") as transport:
            with self.assertRaises(PolicyViolation):
                self.ctx.client.get("https://acme.test/", "fixture", headers={"Host": "other.test"})
            self.camp.policy.proxy = "http://127.0.0.1:8080"
            with self.assertRaises(PolicyViolation):
                self.ctx.client.get("https://acme.test/", "fixture")
            transport.assert_not_called()

    def test_target_transport_cannot_downgrade_to_passive_mode(self):
        self.camp.policy.mode = "passive"
        with self.assertRaises(PolicyViolation):
            self.ctx.client.get("https://acme.test/", "fixture", need="passive")

    def test_intel_cannot_connect_to_private_dns_even_with_target_allow_ranges(self):
        self.camp.policy.allowed_ip_ranges = ["127.0.0.0/8"]
        with patch("recon.egress.socket.getaddrinfo", return_value=self.infos("127.0.0.1")):
            with self.assertRaises(EgressViolation):
                ConnectionGuard(self.camp, self.ctx.store, intel=True).connect(("crt.sh", 443), 1)

    def test_exploit_search_payload_is_not_a_generic_disclosure_channel(self):
        payload = {"query": "nginx 1.18.0", "type": "exploits", "sort": "default", "title": False, "offset": 0}
        with patch.object(self.ctx.passive, "_send") as send:
            self.ctx.passive.post_json("https://sploitus.com/search", payload, "fixture")
            send.assert_called_once()
            with self.assertRaises(PolicyViolation):
                self.ctx.passive.post_json("https://sploitus.com/search", {**payload, "secrets": "anything"}, "fixture")
            with self.assertRaises(PolicyViolation):
                self.ctx.passive.post_json("https://sploitus.com/search", {**payload, "query": "server 10.0.0.1 1.2"}, "fixture")


class RecoveryTests(ReviewBase):
    def test_source_fallback_is_bounded_and_results_recover_after_restart(self):
        fail = MagicMock(side_effect=FetchError("fixture outage"))
        success = MagicMock(return_value=[{"id": "source-item"}])
        runner = SourceRunner(self.ctx)
        result, events = runner.first_result("product 1.2.3", [("first", fail), ("second", success)])
        self.assertEqual(result, [{"id": "source-item"}])
        self.assertEqual(fail.call_count, 2)
        self.assertEqual(success.call_count, 1)
        self.assertEqual(len(events), 3)
        restarted = Recon(self.camp, log=lambda _: None)
        self.addCleanup(restarted.store.close)
        again = SourceRunner(restarted)
        recovered, _ = again.first_result("product 1.2.3", [("first", fail), ("second", success)])
        self.assertEqual(recovered, result)
        self.assertEqual(fail.call_count, 2)
        self.assertEqual(success.call_count, 1)

    def test_policy_or_budget_failure_never_triggers_fallback(self):
        for exc in (PolicyViolation("scope"), BudgetExceeded("budget")):
            fallback = MagicMock(return_value=[])
            with self.assertRaises(PolicyViolation):
                SourceRunner(self.ctx).first_result("product", [
                    ("first", MagicMock(side_effect=exc)), ("second", fallback)], refresh=True)
            fallback.assert_not_called()

    def test_repeated_failures_are_suppressed_and_refresh_is_explicit(self):
        runner = SourceRunner(self.ctx)
        fail = MagicMock(side_effect=ProviderError("invalid fixture result"))
        for _ in range(3):
            runner.first_result("product", [("provider", fail)], refresh=True)
        self.assertEqual(fail.call_count, 6)
        self.assertEqual(self.ctx.store.db.execute("SELECT state FROM provider_cache").fetchone()[0], "stalled")
        runner.first_result("product", [("provider", fail)])
        self.assertEqual(fail.call_count, 6)
        good = MagicMock(return_value=[{"id": "recovered"}])
        result, _ = runner.first_result("product", [("provider", good)], refresh=True)
        self.assertEqual(result[0]["id"], "recovered")

    def test_empty_is_distinct_from_failure(self):
        runner = SourceRunner(self.ctx)
        empty = MagicMock(return_value=[])
        runner.first_result("product", [("provider", empty)])
        runner.first_result("product", [("provider", empty)])
        self.assertEqual(empty.call_count, 1)
        self.assertEqual(self.ctx.store.db.execute("SELECT state FROM provider_cache").fetchone()[0], "empty")

    def test_interrupted_attempt_is_visible_and_retried(self):
        runner = SourceRunner(self.ctx)
        import hashlib
        key = hashlib.sha256(b"product").hexdigest()
        runner._event("provider", key, 1, "started")
        runner.first_result("product", [("provider", lambda: [{"id": "ok"}])])
        states = [r[0] for r in self.ctx.store.db.execute("SELECT state FROM provider_events ORDER BY id")]
        self.assertEqual(states, ["interrupted", "success"])


class CollectionAndRecallTests(ReviewBase):
    def test_exact_entry_path_and_bounded_same_origin_collection(self):
        site = self.root / "site"
        (site / "allowed").mkdir(parents=True)
        (site / "allowed" / "index.html").write_text(
            '<html><a href="two.html">two</a><a href="three.html">three</a>'
            '<a href="/outside">outside</a><a href="/allowed/api/data">API</a></html>')
        (site / "allowed" / "two.html").write_text('<html><script src="two.js"></script></html>')
        (site / "allowed" / "three.html").write_text("<html>must not fetch</html>")
        (site / "allowed" / "two.js").write_text('fetch("/allowed/api/fromsecond")')
        with LabServer(site) as lab:
            base = f"http://127.0.0.1:{lab.port}"
            camp = write_campaign(self.root / "narrow", "active", [base + "/allowed/index.html"],
                                  in_scope=[base + "/allowed"])
            camp.raw["collection"] = {"max_pages": 2, "max_depth": 1}
            ctx = Recon(camp, log=lambda _: None)
            try:
                stats = ctx.run()
                self.assertEqual(stats["failed"], 0)
                self.assertEqual(set(lab.hits), {"/allowed/index.html", "/allowed/two.html", "/allowed/two.js"})
                self.assertTrue(ctx.store.find_asset("endpoint", base + "/allowed/api/fromsecond"))
            finally:
                ctx.store.close()

    def test_contexts_are_not_pooled_and_capture_refs_survive(self):
        fixture = Path(__file__).parent / "fixtures" / "recon" / "alice.har"
        data = json.loads(fixture.read_text().replace("api.example.com", "acme.test"))
        data["log"]["entries"][0]["response"]["content"]["text"] = "DO_NOT_STORE_RAW_RESPONSE"
        har = self.root / "capture.har"
        har.write_text(json.dumps(data))
        for account, role, tenant, workflow in [("alice", "member", "a", "draft"),
                                                ("bob", "member", "b", "draft"),
                                                ("admin", "admin", "a", "draft"),
                                                ("alice", "member", "a", "submitted")]:
            import_har(self.ctx, har, account, role, tenant, workflow)
        self.assertEqual(len(context_param_matrix(self.ctx.store)), 4)
        comparisons = context_comparisons(self.ctx.store)
        self.assertEqual(len(comparisons), 1)
        self.assertEqual(comparisons[0]["principals"], [("alice", "a"), ("bob", "b")])
        observation = self.ctx.store.observations()[0]
        self.assertEqual(observation["context"]["record_index"], 0)
        self.assertTrue(observation["context"]["response_text_sha256"])
        self.assertNotIn("DO_NOT_STORE_RAW_RESPONSE", "\n".join(self.ctx.store.db.iterdump()))
        result = recall(self.ctx, "alice draft")
        self.assertTrue(result["matches"])
        first = result["matches"][0]
        self.assertTrue(first["ref"].startswith("observation:"))
        self.assertTrue(any(ref.startswith("import:") for ref in first["links"]))
        self.assertEqual(len(first["snapshot_sha256"]), 64)

    def test_recall_is_local_and_does_not_promote_inferences(self):
        aid = self.ctx.add_endpoint("https://acme.test/exports", "js", method="GET")
        self.ctx.store.add_fact(aid, "possible tenant export confusion", "inferred", kind="mapping")
        with patch.object(self.ctx.client, "get", side_effect=AssertionError("offline")), \
             patch.object(self.ctx.passive, "get", side_effect=AssertionError("offline")):
            result = recall(self.ctx, "tenant export")
        self.assertEqual(result["mode"], "offline-lexical")
        self.assertEqual(result["matches"][0]["basis"], "inferred")
        with self.assertRaises(ValueError):
            recall(self.ctx, "tenant", limit=100)


class PlanningBoundaryTests(ReviewBase):
    def proposal(self):
        aid = self.ctx.add("js", "https://acme.test/app.js", "html")
        context = snapshot(self.ctx, [aid])
        asset = context["assets"][0]
        return {"schema_version": 1, "scope_sha256": context["scope_sha256"], "jobs": [{
            "asset_id": aid, "asset_sha256": asset["asset_sha256"], "kind": "jsparse", "reason": "parse scoped script"}]}

    def save(self, data):
        path = self.root / "proposal.json"
        path.write_text(json.dumps(data))
        return path

    def test_review_and_apply_never_execute_or_call_models(self):
        data = self.proposal()
        with patch.object(self.ctx.client, "get", side_effect=AssertionError("offline")), \
             patch.object(self.ctx.passive, "get", side_effect=AssertionError("offline")):
            result = review(self.ctx, self.save(data))
            self.assertFalse(result["applied"])
            result = review(self.ctx, self.save(data), apply=True)
            self.assertFalse(result["executed"])
            self.assertFalse(result["intents"][0]["enqueued"])  # already in the unique queue

    def test_scope_and_asset_changes_invalidate_proposals(self):
        data = self.proposal()
        self.ctx.store.update_attrs(data["jobs"][0]["asset_id"], {"changed": True})
        with self.assertRaises(ValueError):
            review(self.ctx, self.save(data))
        data = self.proposal()
        self.camp.policy.mode = "passive"
        with self.assertRaises(ValueError):
            review(self.ctx, self.save(data))

    def test_arbitrary_commands_unknown_handlers_and_oversized_plans_are_rejected(self):
        data = self.proposal()
        data["jobs"][0]["command"] = "curl outside.invalid"
        with self.assertRaises(ValueError):
            review(self.ctx, self.save(data), apply=True)
        data = self.proposal()
        data["jobs"][0]["kind"] = "shell"
        with self.assertRaises(ValueError):
            review(self.ctx, self.save(data), apply=True)
        data = self.proposal()
        data["jobs"] *= 21
        with self.assertRaises(ValueError):
            review(self.ctx, self.save(data), apply=True)


if __name__ == "__main__":
    unittest.main()
