import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon.cli import main
from recon.race import RaceLedger
from tests.invariant_fixtures import artifact, campaign, declaration


def scenario(context, other=None, family="RC-03"):
    return {"schema": 1, "workflow": "coupon", "invariant": "once", "context": context,
            "family": family, "resource": "slot", "order_matters": True,
            "members": [{"operation": "claim", "context": context, "intent": "first"},
                        {"operation": "redeem", "context": other or context, "intent": "second"}]}


def run(sid, context, *, outcome="blocked", parallelism=2, note="owned-fixture blocker"):
    return {"scenario": sid, "schedule": "concurrent", "outcome": outcome, "impact_tier": "T0",
            "members": [{"operation": "claim", "context": context, "intent": "first"},
                        {"operation": "redeem", "context": context, "intent": "second"}],
            "note": note}


class RaceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.ctx = campaign(self.root)
        self.addCleanup(self.ctx.store.close)
        self.race = RaceLedger(self.ctx)
        self.race.model.declare(declaration())
        self.a, self.v = [c["id"] for c in self.race.model.contexts("coupon")]

    def test_exact_writers_shared_resource_and_fanout(self):
        with patch("socket.socket", side_effect=AssertionError("network called")):
            s = self.race.declare(scenario(self.a))
            self.assertEqual(s["members"], 2)
            self.assertTrue(self.race.declare(scenario(self.a))["unchanged"])
            with self.assertRaisesRegex(ValueError, "distinct exact writers"):
                self.race.declare({**scenario(self.a), "members": [
                    {"operation": "claim", "context": self.a, "intent": str(i)} for i in range(3)]})
            with self.assertRaisesRegex(ValueError, "exact resource"):
                self.race.declare({**scenario(self.a), "resource": "elsewhere"})
            with self.assertRaises(ValueError):
                self.race.declare({**scenario(self.a), "members": scenario(self.a)["members"] +
                                   [{"operation": "undeclared", "context": self.a, "intent": "third"}]})

    def test_signals_are_offline_ranked_not_evidence(self):
        endpoint = self.ctx.add_endpoint("http://127.0.0.1:12345/redeem", "har", method="POST")
        self.ctx.store.record_request("POST", "http://127.0.0.1:12345/redeem", 429,
                                      "synthetic-capture", [], {"X-RateLimit-Remaining": "0", "X-Request-Id": "x"},
                                      basis="imported-burp-capture")
        self.race.declare(scenario(self.a))
        self.race.sync()
        profile = self.race.profile("127.0.0.1")
        self.assertTrue(profile["score"])
        self.assertEqual(profile["http2_supported"], "unknown")
        self.assertTrue(any(t["source"] == f"asset:{endpoint}" for t in profile["tells"]))
        self.assertTrue(any(t["kind"] == "response-header" for t in profile["tells"]))
        self.assertEqual(self.race.plan()["rows"][0]["readiness"], "policy-blocked")
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        from recon.campaign import Scope
        self.ctx.scope = Scope.from_lists(["127.0.0.1"], ["/redeem"])
        self.assertEqual(self.race.profile("127.0.0.1")["score"], 0)
        self.assertEqual(self.race.profile("127.0.0.1")["http2_supported"], "unknown")

    def test_candidate_scoring_does_not_promote_get_listing_or_substring_collision(self):
        from recon.score import applicable_classes
        for url in ("http://127.0.0.1:12345/api/orders", "http://127.0.0.1:12345/api/repaymentFacts"):
            scored = applicable_classes({"value": url, "attrs": {"methods": ["GET"]}})
            self.assertNotIn("race-conditions", scored)
        self.assertIn("race-conditions", applicable_classes(
            {"value": "http://127.0.0.1:12345/redeem", "attrs": {"methods": ["GET"]}}))
        self.assertIn("race-conditions", applicable_classes(
            {"value": "http://127.0.0.1:12345/graphql", "attrs": {"methods": ["POST"],
                                                                "graphql_ops": ["mutation GrantEntitlement"]}}))

    def test_measurement_bounds_and_window_classification(self):
        sid = self.race.declare(scenario(self.a))["scenario_id"]
        env = run(sid, self.a)
        with self.assertRaisesRegex(ValueError, "together"):
            self.race.record({**env, "parallelism": 2, "attempts": 2})
        with self.assertRaisesRegex(ValueError, "window evidence"):
            self.race.record({**env, "window_evidence": True})
        with self.assertRaisesRegex(ValueError, "window-evidence"):
            self.race.record({**env, "parallelism": 2, "attempts": 2, "successes": 0,
                              "outcome": "negative-for-variant", "control": "atomicity",
                              "note": "constraint error in owned fixture"})
        with self.assertRaisesRegex(ValueError, "unexecuted review"):
            self.race.record({**env, "parallelism": 2, "attempts": 2, "successes": 0})
        for _ in range(5):
            self.assertEqual(self.race.record(env)["causality"], "unresolved")
        self.assertEqual(self.race.status()["run_total"], 5)
        self.assertEqual(self.race.status()["scenarios"][0]["points"], [])
        self.assertTrue(self.race.verify()["verified"])

    def test_rc21_paired_owned_contexts_only(self):
        self.race.model.declare({**declaration(kind="otp"), "workflow":
                                 {**declaration(kind="otp")["workflow"], "revision": 2}})
        with self.assertRaisesRegex(ValueError, "two separately"):
            self.race.declare(scenario(self.a, family="RC-21"))
        self.assertEqual(self.race.declare(scenario(self.a, self.v, "RC-21"))["members"], 2)


class OperatorAttestationTests(unittest.TestCase):
    """Synthetic imported-capture records, never an actual Burp send or native receipt."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.ctx = campaign(self.root, active=True, grants=True)
        self.addCleanup(self.ctx.store.close)
        self.race = RaceLedger(self.ctx)
        self.race.model.declare(declaration(contexts=False))
        self.ids = []
        for op in ("claim", "redeem"):
            url = f"http://127.0.0.1:12345/{op}"
            eid = self.ctx.add_endpoint(url, "burp", method="POST")
            self.ctx.store.add_observation(eid, "POST", "a", {"query": [], "body":
                                           ["coupon", "quantity"] if op == "claim" else ["coupon"]},
                                           200, "burp", capture_key=f"cap-{op}",
                                           context={"role": "tester", "tenant": "owned", "session": "sa",
                                                    "workflow_state": "new"})
            self.ids.append(self.ctx.store.record_request("POST", url, 200, "synthetic-import", [], {},
                                                         basis="imported-burp-capture",
                                                         context={"account": "a", "role": "tester", "tenant": "owned",
                                                                  "session": "sa"}))
        self.race.model.sync_contexts()
        self.a = self.race.model.contexts("coupon")[0]["id"]
        self.sid = self.race.declare(scenario(self.a))["scenario_id"]

    def attestation(self):
        label = "burp:owned-fixture-gate"
        path = artifact(self.root, "attestation.txt", label + " gated fixture: group-1")
        return {"schema": 1, "scenario": self.sid, "label": label, "tool": "Turbo Intruder",
                "engine": "BURP2", "version": "2.1", "protocol": "HTTP/2", "gate": "group-1",
                "operator": "labowner", "sent": 2, "retries": 0, "requests": 2, "connections": 1,
                "members": [{"operation": op, "context": self.a, "request_id": rid}
                            for op, rid in zip(("claim", "redeem"), self.ids)], "artifact": path}

    def test_attestation_import_uses_external_accounting_once(self):
        before = self.race.model.usage()
        self.assertEqual(before["external_declared"], 0)
        with self.assertRaisesRegex(ValueError, "not target-http"):
            self.race.model.receipts([{"basis": "target-http", "request_id": self.ids[0]}], "native",
                                     self.race.model.operations(self.race.model.workflow("coupon")["id"]),
                                     self.race.model.context(self.a), "")
        with self.assertRaises(ValueError):
            self.race.attest({**self.attestation(), "members": [{**self.attestation()["members"][0],
                                                                  "request_id": 999999},
                                                                 self.attestation()["members"][1]]})
        got = self.race.attest(self.attestation())
        self.assertEqual(got["requests_declared"], 2)
        self.assertEqual(self.race.model.usage()["external_declared"], 2)
        self.assertEqual(self.race.model.usage()["imported_historical"], 0)
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        self.assertTrue(self.race.verify()["verified"])
        # No agent-driven group operation; native concurrent result is refused.
        with self.assertRaisesRegex(ValueError, "agent-driven"):
            self.race.record({**run(self.sid, self.a), "channel": "native"})
        att = self.ctx.store.db.execute("SELECT path FROM race_attestations WHERE id=?",
                                        (got["attestation_id"],)).fetchone()[0]
        (self.root / att).write_text("changed")
        self.assertFalse(self.race.verify()["verified"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["race", "verify", str(self.root)]), 2)

    def test_missing_response_remains_spent_and_blocks_resume_until_reconciled(self):
        data = self.attestation()
        data["members"][1].pop("request_id")
        att = self.race.attest(data)
        self.assertEqual(self.race.model.usage()["external_declared"], 2)
        self.assertEqual(att["unresolved_members"], 1)
        self.assertTrue(self.race.model.active_stop("127.0.0.1"))
        with self.assertRaisesRegex(ValueError, "no reconciled run"):
            self.race.model.resume("127.0.0.1", "unsupported early resume")
        with self.assertRaisesRegex(ValueError, "already attested"):
            self.race.attest(data)
        marker = "uncertain_owned_000001"
        ref = run(self.sid, self.a, outcome="inconclusive", note="second response missing")
        ref.update({"channel": "burp", "attestation": att["attestation_id"], "marker": marker,
                    "facts": {"effected": "unknown"}, "stop_trigger": "observer-lost",
                    "members": [{**ref["members"][0], "request_id": self.ids[0]}, ref["members"][1]],
                    "receipts": [{"basis": "external-declared", "label": data["label"], "requests": 2},
                                 {"basis": "imported-burp-capture", "request_id": self.ids[0]}]})
        with self.assertRaisesRegex(ValueError, "missing member response"):
            self.race.record({**ref, "outcome": "blocked", "facts": {}, "stop_trigger": "observer-lost"})
        with self.assertRaisesRegex(ValueError, "missing member response"):
            self.race.record({**ref, "facts": {}, "stop_trigger": "observer-lost"})
        result = self.race.record(ref)
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(self.race.model.usage()["external_declared"], 2)
        self.assertEqual(self.race.model.usage()["imported_historical"], 1)
        with self.assertRaisesRegex(ValueError, "one attested gate"):
            self.race.record(ref)
        with self.assertRaisesRegex(ValueError, "unknown effect"):
            self.race.model.resume("127.0.0.1", "reviewed")
        receipt = artifact(self.root, "reconcile.txt", marker + " no additional owned effect")
        self.race.model.cleanup(result["event_id"], "reconciled", receipt)
        self.assertEqual(self.race.model.resume("127.0.0.1", "owner oracle reconciled")["host"],
                         "127.0.0.1")
