"""Scope, shared-budget and header-isolation regressions (offline or owned loopback)."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon.campaign import ConfigError, OutOfScope, PolicyViolation, Scope, scope_template
from recon.net import BudgetExceeded, RequestBudget, Response
from recon.pipeline import Recon
from recon.runtime import job_runtime
from tests.test_recon import LabServer, write_campaign


class ScopeBoundaryTests(unittest.TestCase):
    def test_url_scope_preserves_explicit_and_default_ports(self):
        scope = Scope.from_lists(["https://api.acme.com:8443/v1", "https://web.acme.com"], [])
        self.assertTrue(scope.is_in("https://api.acme.com:8443/v1/users"))
        self.assertFalse(scope.is_in("https://api.acme.com/v1/users"))
        self.assertTrue(scope.is_in("https://web.acme.com:443/"))
        self.assertFalse(scope.is_in("https://web.acme.com:8443/"))
        self.assertFalse(scope.is_in("http://web.acme.com/"))

    def test_bare_hosts_and_port_exclusions(self):
        scope = Scope.from_lists(["api.acme.com"], ["api.acme.com:8443"])
        self.assertTrue(scope.is_in("https://api.acme.com:9443/x"))
        self.assertFalse(scope.is_in("http://api.acme.com:8443/x"))

    def test_ipv6_and_bad_ports_and_userinfo(self):
        self.assertTrue(Scope.from_lists(["::1"], []).is_in("http://[::1]:8080/"))
        scope = Scope.from_lists(["api.acme.com"], [])
        for url in ("https://user:secret@api.acme.com/", "https://api.acme.com:bad/",
                    "https://api.acme.com:0/"):
            self.assertFalse(scope.is_in(url))
        for rule in ("https://user:secret@api.acme.com", "api.acme.com:bad", "api.acme.com:0"):
            with self.assertRaises(ConfigError):
                Scope.from_lists([rule], [])

    def test_seed_template_does_not_authorize_wildcard(self):
        template = scope_template("lab", ["acme.com"], "passive")
        self.assertEqual(template["in_scope"], ["acme.com"])
        self.assertFalse(template["runtime"]["enabled"])

    def test_path_only_allow_rules_are_rejected(self):
        with self.assertRaises(ConfigError):
            Scope.from_lists(["/api"], [])


class ClientBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        camp = write_campaign(self.root / "campaign", "active", [], in_scope=["*.acme.com"])
        camp.policy.headers = {"Authorization": "Bearer SECRET", "X-Private": "PRIVATE"}
        self.ctx = Recon(camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)

    def test_passive_provider_never_gets_target_headers(self):
        with patch.object(self.ctx.passive, "_send") as send:
            self.ctx.passive.get("https://crt.sh/?q=acme.com", "test")
        headers = send.call_args.args[3]
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("X-Private", headers)

    def test_passive_provider_refuses_target_even_with_narrow_url_scope(self):
        self.ctx.campaign.scope = Scope.from_lists(["http://crt.sh:8080/private"], [])
        with self.assertRaises(PolicyViolation):
            self.ctx.passive.get("https://crt.sh/", "test")

    def test_cross_origin_redirect_strips_custom_headers(self):
        responses = [Response("https://a.acme.com/", 302, {"location": "https://b.acme.com/"}, b""),
                     Response("https://b.acme.com/", 200, {}, b"ok")]
        with patch.object(self.ctx.client, "_send", side_effect=responses) as send:
            self.ctx.client.get("https://a.acme.com/", "test")
        first, second = [call.args[3] for call in send.call_args_list]
        self.assertIn("Authorization", first)
        self.assertNotIn("Authorization", second)
        self.assertNotIn("X-Private", second)

    def test_same_origin_redirect_keeps_configured_headers(self):
        responses = [Response("https://a.acme.com/", 302, {"location": "/next"}, b""),
                     Response("https://a.acme.com/next", 200, {}, b"ok")]
        with patch.object(self.ctx.client, "_send", side_effect=responses) as send:
            self.ctx.client.get("https://a.acme.com/", "test")
        self.assertIn("Authorization", send.call_args_list[1].args[3])

    def test_request_budget_is_shared_and_enforced_before_transport(self):
        self.assertIs(self.ctx.client.budget, self.ctx.passive.budget)
        self.ctx.client.budget.remaining = 1
        self.ctx.client.budget.consume()
        with patch.object(self.ctx.passive.opener, "open") as transport:
            with self.assertRaises(BudgetExceeded):
                self.ctx.passive.get("https://crt.sh/", "test")
        transport.assert_not_called()

    def test_runtime_requires_opt_in_even_if_package_is_installed(self):
        with self.assertRaises(PolicyViolation):
            job_runtime(self.ctx, {"id": 1, "value": "https://a.acme.com", "attrs": {}})

    def test_deadline_budget(self):
        with patch("recon.net.time.monotonic", return_value=10):
            budget = RequestBudget(10, 5)
        with patch("recon.net.time.monotonic", return_value=16):
            with self.assertRaises(BudgetExceeded):
                budget.consume()

    def test_loopback_queue_stops_at_request_budget(self):
        site = self.root / "site"
        site.mkdir()
        (site / "index.html").write_text("<html>lab</html>")
        with LabServer(site) as lab:
            base = f"http://127.0.0.1:{lab.port}"
            camp = write_campaign(self.root / "bounded", "active", [base], in_scope=[base])
            camp.policy.max_requests = 1
            ctx = Recon(camp, log=lambda _: None)
            try:
                stats = ctx.run()
                self.assertEqual(len(lab.hits), 1)
                self.assertEqual(ctx.store.request_count(), 1)
                self.assertEqual(stats["skipped"], 1)
                self.assertTrue(any(j["state"] == "queued" for j in ctx.store.jobs()))
            finally:
                ctx.store.close()


if __name__ == "__main__":
    unittest.main()
