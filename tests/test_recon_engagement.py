"""Offline orchestrator foundation: no target traffic or model dispatch."""
import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon.campaign import Campaign, PolicyViolation, Scope, scope_template
from recon.cli import main
from recon.engagement import Engagement
from recon.pipeline import Recon
from recon.planning import digest, scope_revision
from recon.push import budget_snapshot, context, review


class EngagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.root.mkdir()
        cfg = scope_template("owned-offline-fixture", ["https://app.example.test/"], "active")
        cfg["in_scope"].append("api.example.test")
        cfg["policy"]["max_campaign_requests"] = 30
        cfg["policy"]["max_requests"] = 20
        (self.root / "scope.json").write_text(json.dumps(cfg))
        self.ctx = Recon(Campaign.load(self.root), log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.eng = Engagement(self.ctx, "trial")
        self.eng.init()
        self.url = "https://app.example.test/api/render"
        self.aid = self.ctx.add_endpoint(self.url, "har", method="GET", params=["template"])
        self.ctx.refresh_coverage()

    def manifest(self):
        return {"schema_version": 1, "scope_sha256": scope_revision(self.ctx),
                "budget_sha256": digest(budget_snapshot(self.ctx)), "pushes": [{
                    "class": "ssti", "asset_id": self.aid,
                    "asset_sha256": digest(self.ctx.store.get_asset(self.aid)),
                    "endpoint": self.url, "method": "GET", "skill": "hunt-ssti",
                    "model": "claude", "intent": "verify marker with own account",
                    "predicate": {"type": "status_is", "expected": 200}, "poe_target": 1,
                    "request_budget": 2, "debt_items": [f"coverage:{self.aid}:ssti"],
                    "reason": "observed render input"}]}

    def save(self, manifest):
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest))
        return path

    def test_checkpoint_is_private_resumable_and_scope_bound(self):
        self.assertEqual(self.eng.checkpoint()["phase"], "offline-foundation")
        self.assertTrue(str(self.eng.path).startswith(str(self.root / ".recon")))
        with self.assertRaises(ValueError):
            self.eng.init()
        with self.assertRaises(ValueError):
            Engagement(self.ctx, "../../escape")
        self.ctx.campaign.raw["rules"].append("new rule requiring review")
        self.assertTrue(self.eng.checkpoint()["scope_changed"])
        with self.assertRaises(ValueError):
            self.eng.categorise()
        self.assertFalse(self.eng.acknowledge_scope()["scope_changed"])

    def test_delta_retags_without_relabelling_every_asset(self):
        aid = self.ctx.add_endpoint("https://app.example.test/signup", "har", method="GET")
        first = self.eng.categorise()
        self.assertEqual(first["processed"], 2)
        self.assertEqual(self.eng.categorise()["processed"], 0)
        self.ctx.store.update_attrs(aid, {"api_like": True})
        delta = self.eng.categorise()
        self.assertEqual(delta["processed"], 1)
        self.assertEqual(delta["changes"][0]["added"], ["api"])
        self.assertEqual(delta["changes"][0]["basis"], {"api": "asset-attribute"})
        self.assertTrue(self.eng.reconcile()["items"])
        self.assertEqual(self.eng.categorise()["processed"], 0)

    def test_scope_acknowledgement_forces_rescan_not_stale_tags(self):
        self.eng.categorise()
        self.assertIn(str(self.aid), json.loads(self.eng.categories_file.read_text())["assets"])
        self.ctx.campaign.raw["out_of_scope"] = ["/api/render"]
        self.ctx.campaign.scope = Scope.from_lists(self.ctx.campaign.raw["in_scope"],
                                                    self.ctx.campaign.raw["out_of_scope"])
        self.ctx.scope = self.ctx.campaign.scope
        self.eng.acknowledge_scope()
        self.assertEqual(self.eng.categorise()["processed"], 1)
        self.assertNotIn(str(self.aid), json.loads(self.eng.categories_file.read_text())["assets"])

    def test_debt_uses_existing_coverage_matrix_and_blocked_host(self):
        debt = self.eng.reconcile()
        ids = {i["id"] for i in debt["items"]}
        self.assertIn(f"coverage:{self.aid}:ssti", ids)
        self.assertIn("matrix:render:list", ids)
        self.assertEqual(debt["sources"], ["coverage", "fields.matrix", "fields.surface_matrix",
                                            "authpolicy.plan", "chain.status", "categories.delta"])
        rid = self.ctx.store.record_request("GET", self.url, 429, "offline-import", [], {},
                                            basis="imported-burp-capture")
        with self.assertRaises(ValueError):
            self.eng.block_host(rid, "challenge")
        self.eng.block_host(rid, "429")
        debt = self.eng.reconcile()
        self.assertIn("blocked-host:app.example.test", {i["id"] for i in debt["items"]})
        item = next(i for i in debt["items"] if i["id"] == f"coverage:{self.aid}:ssti")
        self.assertIn("deferred", item["blocked_reason"])

    def test_valid_manifest_is_offline_review_receipt_only(self):
        self.assertIn(f"coverage:{self.aid}:ssti", {i["id"] for i in context(self.ctx, self.eng)["debt"]})
        with patch.object(self.ctx.client, "request", side_effect=AssertionError("no send")), \
             patch.object(self.ctx.client, "get", side_effect=AssertionError("no send")):
            result = review(self.ctx, self.save(self.manifest()), self.eng, apply=True)
        self.assertTrue(result["validated"])
        self.assertFalse(result["executed"])
        self.assertEqual(result["total_request_budget"], 2)
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        receipt = self.eng.path / "push-authorizations" / (result["manifest_sha256"] + ".json")
        self.assertTrue(receipt.is_file())
        self.assertFalse(json.loads(receipt.read_text())["traffic_granted"])

    def test_manifest_fails_closed_without_partial_receipt(self):
        manifest = self.manifest()
        mutations = (
            lambda m: m["pushes"][0].update({"command": "curl x"}),
            lambda m: m["pushes"][0].update({"predicate": {"type": "duration_exceeds", "ms": 10}}),
            lambda m: m["pushes"][0].update({"skill": "hunt-sqli"}),
            lambda m: m["pushes"][0].update({"request_budget": 40}),
            lambda m: m["pushes"][0].update({"endpoint": "https://other.test/api/render"}),
            lambda m: m["pushes"][0].update({"method": "POST"}),
            lambda m: m["pushes"].append(copy.deepcopy(m["pushes"][0])),
            lambda m: m["pushes"][0].update({"debt_items": ["coverage:99:ssti"]}),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                trial = copy.deepcopy(manifest)
                mutate(trial)
                with self.assertRaises((ValueError, PolicyViolation)):
                    review(self.ctx, self.save(trial), self.eng, apply=True)
        self.assertFalse((self.eng.path / "push-authorizations").exists())
        self.ctx.store.reserve_network_attempt(30)
        with self.assertRaises(ValueError):
            review(self.ctx, self.save(manifest), self.eng)

    def test_changed_asset_and_429_invalidate_batch(self):
        manifest = self.manifest()
        self.ctx.store.update_attrs(self.aid, {"new": "tag"})
        with self.assertRaises(ValueError):
            review(self.ctx, self.save(manifest), self.eng)
        manifest = self.manifest()
        rid = self.ctx.store.record_request("GET", self.url, 429, "offline-import", [], {},
                                            basis="imported-burp-capture")
        self.eng.block_host(rid, "429")
        with self.assertRaises(PolicyViolation):
            review(self.ctx, self.save(manifest), self.eng)
        other = self.ctx.add_endpoint("https://api.example.test/api/render", "har",
                                      method="GET", params=["template"])
        self.ctx.refresh_coverage()
        manifest["pushes"][0].update({"asset_id": other,
                                     "asset_sha256": digest(self.ctx.store.get_asset(other)),
                                     "endpoint": "https://api.example.test/api/render",
                                     "debt_items": [f"coverage:{other}:ssti"]})
        self.assertTrue(review(self.ctx, self.save(manifest), self.eng)["validated"])

    def test_cli_commands_work_without_target_access(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["engagement", "status", str(self.root), "--id", "trial"]), 0)
            self.assertEqual(main(["push", "validate", str(self.root), "--engagement", "trial",
                                   "--manifest", str(self.save(self.manifest()))]), 0)


if __name__ == "__main__":
    unittest.main()
