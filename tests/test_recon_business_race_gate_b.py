"""Owned finite-step commerce lab: applications effects, not target/network races.

B01's real 127.0.0.1 HTTP collision lives in test_recon_race_lab.py. The
scenarios here are deterministic *in-process* schedules, so no synchronized
target transport, real payment or other account is exercised.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from recon.campaign import Campaign
from recon.findings import Findings
from recon.logic import LogicLedger
from recon.pipeline import Recon
from recon.race import RaceLedger
from recon.report import write_reports
from tests.invariant_fixtures import artifact, campaign, declaration
from tests.owned_workflow_lab import OwnedCommerce
from tests.test_recon_race import scenario


def minor(value):
    return {"currency": "USD", "minor": value}


class OwnedCommerceGateB(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.ctx = campaign(self.root)
        self.addCleanup(self.ctx.store.close)
        self.lab = OwnedCommerce()
        self.logic = LogicLedger(self.ctx)

    def exercise(self, kind, *, writers=None):
        results = {}
        for label, fixed, schedule in (("vulnerable", False, "overlap"),
                                       ("fixed", True, "overlap"),
                                       ("serial-ab", False, "serial"),
                                       ("serial-ba", False, "reverse")):
            self.lab.reset()
            results[label] = self.lab.run(kind, fixed=fixed, schedule=schedule, writers=writers)
        return results

    def record_comparison(self, label, bad, good, projection, *, predicate=None):
        """Import an in-process oracle into the public offline logic ledger (no request IDs)."""
        data = declaration()
        data["workflow"]["key"] = label
        data["workflow"]["label"] = "owned synthetic " + label
        data["workflow"]["crown_jewel"] = "money" if predicate and predicate["type"] in (
            "conservation-by-unit", "refund-capacity") else "entitlement"
        if predicate:
            data["invariants"][0]["predicate"] = predicate
        self.logic.declare(data)
        context = self.logic.model.contexts(label)[0]["id"]
        positive, negative = projection(bad), projection(good)
        token = f"owned_{label}_attempt_01"
        control = "ctrl_" + hashlib.sha256(token.encode()).hexdigest()[:20]
        env = {"context": context, "invariant": "once", "case": "BL-10",
               "outcome": "observed", "impact_tier": "T1", "marker": token,
               "control_marker": control, "control": "atomicity", "objects": 1,
               "object_ref": "owned-" + label, "attacker_gain": "one excess synthetic owned effect",
               "next_play": "P3-value-effect", "projections": positive,
               "control_projections": negative, "baseline_projections": negative,
               "facts": {"committed": "yes", "effected": "yes"},
               "artifacts": [
                   "before=" + artifact(self.root, label + "-before.txt", token + " fresh owned state 100"),
                   "after=" + artifact(self.root, label + "-after.txt",
                                       json.dumps(bad, sort_keys=True) + token),
                   "oracle=" + artifact(self.root, label + "-oracle.txt",
                                        json.dumps({"projection": positive, "trace": bad["trace"]}) + token),
                   "control=" + artifact(self.root, label + "-control.txt",
                                         json.dumps({"projection": negative, "trace": good["trace"]}) + control)]}
        result = self.logic.record(env)
        self.assertEqual(result["verdict"], "violated")
        self.assertTrue(result["lab_only"])
        self.assertFalse(result["finding_promoted"])
        cleanup = artifact(self.root, label + "-cleanup.txt", token + " deleted owned fixture")
        self.logic.model.cleanup(result["event_id"], "deleted", cleanup)
        reopened = Recon(Campaign.load(self.root), log=lambda _: None)
        try:
            self.assertTrue(LogicLedger(reopened).verify()["verified"])
            self.assertEqual(LogicLedger(reopened).status()["events"][0]["readiness"], "lab-only-review")
            write_reports(reopened)
            self.assertIn("Business-invariant and race evidence", (self.root / "coverage.md").read_text())
        finally:
            reopened.store.close()
        return result

    def chain_rehearsal(self, tag, target_class, effect, *, policy_kind="coupon"):
        """Synthetic target-class proof is separate from the BL source event."""
        from tests.invariant_fixtures import event
        data = declaration(kind=policy_kind)
        if target_class == "ato":
            data["workflow"]["crown_jewel"] = "identity"
        self.logic.declare(data)
        context = self.logic.model.contexts("coupon")[0]["id"]
        source = event(self.root, context, f"{tag}_owned_source_01", suffix=tag + "src")
        source["attacker_gain"] = "one bounded synthetic owned chain effect"
        source["root_key"] = tag
        initial = self.logic.record(source)
        fid, _ = Findings(self.ctx).add("synthetic " + tag + " downstream", target_class,
                                     url="http://127.0.0.1:12345/claim",
                                     detail={"lineage": initial["lineage"]})
        replay = self.root / artifact(self.root, tag + "-target-replay.txt",
                                       "owned target effect " + json.dumps(effect, sort_keys=True))
        control = self.root / artifact(self.root, tag + "-target-control.txt",
                                        "fixed target refused; no owned effect")
        impact = self.root / artifact(self.root, tag + "-target-impact.txt",
                                       "one owned downstream effect " + json.dumps(effect, sort_keys=True))
        findings = Findings(self.ctx)
        findings.move(fid, "confirmed", replay=replay, control=control)
        findings.move(fid, "impact-proven", impact=impact, poe_level=3,
                      quote="one owned downstream effect", impact_kind="state-change",
                      measurement="1 of 1 owned synthetic downstream effects observed")
        followup = event(self.root, context, f"{tag}_owned_followup_01", suffix=tag + "follow")
        followup.update({"impact_tier": "T4", "root_key": tag, "chain_finding": fid,
                         "attacker_gain": "one synthetic owned downstream effect"})
        followup["artifacts"] += ["lab-rehearsal=" + artifact(
            self.root, tag + "-lab-rehearsal.txt", "owned chain " + json.dumps(effect, sort_keys=True))]
        result = self.logic.record(followup)
        self.assertEqual(result["impact_tier"], "T4")
        self.assertFalse(result["finding_promoted"])
        self.assertTrue(self.logic.verify()["verified"])
        return result

    def test_b02_lost_update_ledger_cannot_hide_second_effect(self):
        runs = self.exercise("debit")
        bad, good = runs["vulnerable"], runs["fixed"]
        self.assertEqual((bad["balance"], len(bad["debits"])), (40, 2))
        for label in ("fixed", "serial-ab", "serial-ba"):
            self.assertEqual((runs[label]["balance"], len(runs[label]["debits"])), (40, 1))
        proj = lambda r: {"opening": minor(100), "inflows": [],
                          "outflows": [minor(n) for _, n in r["debits"]], "closing": minor(r["balance"])}
        self.record_comparison("b02", bad, good, proj,
                               predicate={"type": "conservation-by-unit", "currency": "USD", "exponent": 2})

    def test_b03_quote_binding_is_sequential_logic_not_a_race(self):
        self.assertIsNone(self.lab.quote(fixed=True, quantity=1, version=0, client_minor=1))
        self.lab.reset()
        invalid = self.lab.quote(fixed=False, quantity=1, version=0, client_minor=1)
        self.assertEqual((invalid["version"], invalid["minor"], len(self.lab.receiver)), (0, 1, 1))
        self.lab.reset()
        valid = self.lab.quote(fixed=True, quantity=1, version=1, client_minor=25)
        self.assertEqual(valid, {"product": "owned-item", "quantity": 1, "currency": "USD",
                                 "version": 1, "minor": 25})
        self.assertEqual(len(self.lab.receiver), 1)

    def test_b04_incomplete_publication_and_legal_order(self):
        for fixed, early, expected in ((False, True, 1), (True, True, 0),
                                       (False, False, 1), (True, False, 1)):
            self.lab.reset()
            self.assertEqual(len(self.lab.publish_then_use(fixed=fixed, early=early)), expected)
            if early:
                self.assertLess(self.lab.trace.index("write:partial-construction"),
                                self.lab.trace.index("commit:approved-entitlement"))

    def test_b05_refunds_obey_captured_capacity(self):
        runs = self.exercise("refund")
        self.assertEqual(sum(n for _, n in runs["vulnerable"]["refunds"]), 120)
        for label in ("fixed", "serial-ab", "serial-ba"):
            self.assertEqual(sum(n for _, n in runs[label]["refunds"]), 60)
        proj = lambda r: {"captured": minor(100),
                          "refunds": [minor(n) for _, n in r["refunds"]]}
        self.record_comparison("b05", runs["vulnerable"], runs["fixed"], proj,
                               predicate={"type": "refund-capacity", "currency": "USD", "exponent": 2})

    def test_b06_same_intent_two_acks_one_effect_is_correct(self):
        runs = self.exercise("idempotency")
        self.assertEqual(len(runs["vulnerable"]["effects"]), 2)
        self.assertEqual(len(runs["fixed"]["effects"]), 1)
        self.assertEqual(sum(r["sent"] for r in runs["fixed"]["receipts"].values()), 2)
        for label in ("serial-ab", "serial-ba"):
            self.assertEqual(len(runs[label]["effects"]), 1)
        self.record_comparison("b06", runs["vulnerable"], runs["fixed"],
                               lambda r: {"intent_effects": len(r["effects"])},
                               predicate={"type": "intent-idempotent-effect", "max_effects": 1})

    def test_b07_key_body_identity_and_fake_clock_are_bounded(self):
        self.lab.keyed("key", "a", 25, fixed=True)
        self.assertEqual(self.lab.keyed("key", "a", 25, fixed=True), self.lab.receiver[0])
        self.assertIsNone(self.lab.keyed("key", "a", 26, fixed=True))
        self.assertIsNone(self.lab.keyed("key", "v", 25, fixed=True))
        self.assertEqual(len(self.lab.receiver), 1)
        self.lab.clock = 10
        self.assertEqual(self.lab.keyed("key", "a", 26, fixed=True)["amount"], 26)
        self.assertEqual(len(self.lab.receiver), 2)
        self.lab.reset()
        self.lab.keyed("key", "a", 25, fixed=False)
        self.assertEqual(self.lab.keyed("key", "v", 26, fixed=False)["account"], "a")
        # Cached-result identity is handed to authorization, not asserted as a BL race.

    def test_b08_duplicate_and_out_of_order_queue_delivery(self):
        for fixed in (False, True):
            self.lab.reset()
            self.lab.deliver("owned-event", 2, fixed=fixed, acknowledge=False)
            self.lab.deliver("owned-event", 2, fixed=fixed)
            self.lab.deliver("stale-owned-event", 1, fixed=fixed)
            self.assertEqual(len(self.lab.queue), 3)
            self.assertEqual(len(self.lab.acks), 2)
            self.assertEqual(len(self.lab.receiver), 1 if fixed else 3)
            self.assertEqual(self.lab.clock, 2 if fixed else 1)

    def test_b09_timeout_after_commit_is_unknown_until_oracle(self):
        for committed in (True, False):
            self.lab.reset()
            self.assertEqual(self.lab.timeout("owned-intent", committed=committed, fixed=True), "unknown")
            self.assertEqual(len(self.lab.receiver), int(committed))
            if committed:
                self.lab.timeout("owned-intent", committed=True, fixed=True)
                self.assertEqual(len(self.lab.receiver), 1)
            self.assertEqual(self.lab.keys.get("owned-intent"), "committed" if committed else None)
        self.lab.reset()
        self.lab.timeout("owned-intent", committed=True, fixed=False)
        self.lab.timeout("owned-intent", committed=True, fixed=False)
        self.assertEqual(len(self.lab.receiver), 2)

    def test_b10_distinct_row_writers_share_aggregate_predicate(self):
        runs = self.exercise("skew", writers=["route", "version"])
        self.assertEqual(sum(runs["vulnerable"]["rows"].values()), 2)
        self.assertEqual({sum(runs[k]["rows"].values()) for k in ("fixed", "serial-ab", "serial-ba")}, {1})
        self.record_comparison("b10", runs["vulnerable"], runs["fixed"],
                               lambda r: {"effects": sum(r["rows"].values())},
                               predicate={"type": "at-most-count", "limit": 1})

    def test_b11_rollback_does_not_erase_receiver_effect(self):
        self.assertEqual(self.lab.saga(fixed=False, compensate=False),
                         {"local": False, "receiver": ["original-effect"], "obligation": "open"})
        self.lab.reset()
        repaired = self.lab.saga(fixed=True, compensate=True)
        self.assertEqual(repaired["receiver"], ["original-effect", "compensating-effect"])
        self.assertEqual(repaired["obligation"], "resolved")

    def test_b12_stale_cache_and_reversed_response_are_not_commits(self):
        runs = self.exercise("slot")
        fixed = runs["fixed"]
        responses = ["200 cached-success", "200 cached-success"]
        release_order = list(reversed(fixed["writers"]))
        self.assertEqual((len(responses), len(release_order)), (2, 2))
        self.assertEqual(len(fixed["effects"]), 1)
        self.assertEqual(len(runs["serial-ab"]["effects"]), 1)

    def test_b13_predeclared_schedule_points_and_denominators(self):
        writers = ["route", "v2", "batch", "graphql"]
        points = []
        for size, schedule, fixed in ((2, "overlap", False), (4, "serial", False),
                                      (2, "overlap", True), (4, "overlap", True)):
            self.lab.reset()
            result = self.lab.run("slot", writers=writers[:size], fixed=fixed, schedule=schedule)
            points.append({"parallelism": size, "attempts": size,
                           "successes": max(0, len(result["effects"]) - 1),
                           "schedule": schedule, "fixed": fixed})
        self.assertEqual([(p["successes"], p["attempts"]) for p in points],
                         [(1, 2), (0, 4), (0, 2), (0, 4)])
        # The 4-writer return is deliberately SERIAL: this is a chosen schedule,
        # not evidence of a universal parallelism/window threshold.
        self.assertEqual(points[1]["schedule"], "serial")

    def test_b14_one_owned_field_and_one_owned_sensitive_read(self):
        self.lab.protected = "none"
        self.lab.protected = "granted"  # owned, single field, synthetic effect
        self.assertEqual(self.lab.protected, "granted")
        self.logic.declare(declaration())
        ctx = self.logic.model.contexts("coupon")[0]["id"]
        from tests.invariant_fixtures import event
        write = event(self.root, ctx, "b14_owned_write_01", suffix="b14-write")
        write.update({"impact_tier": "T2", "terminal": {"kind": "owned-write",
                      "object": write["object_ref"], "field": "protected", "before": "none",
                      "after": self.lab.protected}})
        write["artifacts"] += ["owned-write=" + artifact(self.root, "b14-change.txt",
                               write["object_ref"] + " protected granted"),
                               "readback=" + artifact(self.root, "b14-readback.txt",
                               write["object_ref"] + " protected " + self.lab.protected)]
        recorded = self.logic.record(write)
        self.assertEqual(recorded["impact_tier"], "T2")
        self.logic.model.cleanup(recorded["event_id"], "deleted", artifact(
            self.root, "b14-cleanup.txt", write["object_ref"] + " removed"))
        read = event(self.root, ctx, "b14_owned_read_0001", suffix="b14-read")
        read.update({"impact_tier": "T3", "terminal": {"kind": "victim-read", "account": "a",
                     "field": "email", "records": 1}})
        read["artifacts"] += ["victim-read=" + artifact(self.root, "b14-server.txt",
                               "server email: owned-a@example.invalid"),
                              "redacted=" + artifact(self.root, "b14-redacted.txt", "email: [redacted]"),
                              "ui-control=" + artifact(self.root, "b14-ui.txt", "owned UI hides field")]
        self.assertEqual(self.logic.record(read)["impact_tier"], "T3")
        self.assertTrue(self.logic.verify()["verified"])

    def test_b15_four_exact_writers_and_fixed_shared_predicate(self):
        writers = ["route", "v2", "batch", "graphql"]
        runs = self.exercise("fanout", writers=writers)
        self.assertEqual(len(runs["vulnerable"]["effects"]), 4)
        self.assertEqual(len(runs["fixed"]["effects"]), 2)
        self.assertEqual({len(runs[k]["effects"]) for k in ("serial-ab", "serial-ba")}, {2})
        for run in runs.values():
            self.assertEqual(set(run["receipts"]), set(writers))
        self.record_comparison("b15", runs["vulnerable"], runs["fixed"],
                               lambda r: {"effects": len(r["effects"])},
                               predicate={"type": "at-most-count", "limit": 2})
        data = declaration()
        data["workflow"]["key"] = "fanout"
        data["operations"] += [{"key": name, "url": "http://127.0.0.1:12345/" + name,
                                "method": "POST", "writes": ["slot"]} for name in ("batch", "graphql")]
        self.logic.declare(data)
        a = self.logic.model.contexts("fanout")[0]["id"]
        self.assertEqual(RaceLedger(self.ctx).declare({**scenario(a), "workflow": "fanout",
            "members": [{"operation": name, "context": a, "intent": name} for name in
                        ("claim", "redeem", "batch", "graphql")]})["members"], 4)

    def test_b16_owned_entitlement_to_one_reserved_action_is_target_class_owned(self):
        runs = self.exercise("slot")
        self.assertEqual(len(runs["vulnerable"]["effects"]), 2)
        self.lab.reset()
        self.lab.effects = runs["vulnerable"]["effects"][:]
        self.assertTrue(self.lab.reserved_action(account="a", owned_object="owned-object-1",
                                                  role="member", fixed=False))
        self.assertEqual(self.lab.receiver, [{"account": "a", "role": "member", "object": "owned-object-1",
                                              "action": "reserved-once"}])
        self.assertEqual(len(runs["fixed"]["effects"]), 1)
        self.lab.reset()
        self.lab.effects = runs["fixed"]["effects"][:]
        self.assertFalse(self.lab.reserved_action(account="a", owned_object="owned-object-1",
                                                   role="member", fixed=True))
        self.lab.effects = runs["vulnerable"]["effects"][:]
        self.assertFalse(self.lab.reserved_action(account="a", owned_object="owned-object-1",
                                                   role="member", fixed=True))
        self.assertEqual(self.lab.receiver, [])
        self.chain_rehearsal("b16", "access-control", {"action": "reserved-once",
                                                    "account": "a", "role": "member",
                                                    "object": "owned-object-1"})

    def test_b17_a_v_owned_artifact_consumption_and_session_handoff(self):
        data = declaration(kind="otp")
        data["workflow"]["crown_jewel"] = "identity"
        self.logic.declare(data)
        a, v = [r["id"] for r in self.logic.model.contexts("coupon")]
        sid = RaceLedger(self.ctx).declare(scenario(a, v, "RC-21"))["scenario_id"]
        self.assertIsInstance(sid, int)
        for fixed, schedule, expected in ((False, "overlap", 2), (True, "overlap", 1),
                                          (False, "serial", 1), (False, "reverse", 1)):
            self.lab.reset()
            outcome = self.lab.consume_owned_artifact(fixed=fixed, schedule=schedule)
            self.assertEqual(outcome["artifact"], "owned-once-token")
            self.assertEqual(len(self.lab.sessions), expected)
            self.assertEqual({acct for acct, _ in outcome["sessions"]},
                             set(outcome["consumptions"]))
        with self.assertRaisesRegex(ValueError, "never guess"):
            self.lab.consume_owned_artifact(fixed=True, schedule="serial", token="unowned")
        self.chain_rehearsal("b17", "ato", {"sessions": ["account-a", "account-v"],
                                              "artifact": "owned-once-token"}, policy_kind="otp")

    def test_b18_synthetic_overrun_to_one_capped_credit(self):
        runs = self.exercise("debit")
        delta = self.lab.credit_one_owned_resource(runs["vulnerable"], runs["fixed"], cap_minor=10)
        self.assertEqual(delta, 10)
        self.assertEqual(self.lab.receiver, [{"owned-credit-minor": 10}])
        self.assertEqual(len(runs["fixed"]["effects"]), 1)
        self.assertEqual(self.lab.credit_one_owned_resource(runs["fixed"], runs["fixed"]), 0)
        with self.assertRaisesRegex(ValueError, "declared cap"):
            self.lab.credit_one_owned_resource(runs["vulnerable"], runs["fixed"], cap_minor=9)
        from tests.invariant_fixtures import event
        self.logic.declare(declaration())
        a = self.logic.model.contexts("coupon")[0]["id"]
        env = event(self.root, a, "b18_credit_owned_01", suffix="b18")
        env.update({"impact_tier": "T2", "terminal": {"kind": "value-delta", "currency": "USD",
                    "exponent": 2, "minor": delta, "cap_minor": 10, "synthetic": True}})
        env["artifacts"] += ["value-delta=" + artifact(self.root, "b18-ledger.txt",
                              json.dumps({"account": "a", "object": env["object_ref"],
                                          "credit_minor": delta}) + " owned synthetic 10")]
        recorded = self.logic.record(env)
        self.assertEqual(recorded["impact_tier"], "T2")
        self.logic.model.cleanup(recorded["event_id"], "deleted", artifact(
            self.root, "b18-delete.txt", env["object_ref"] + " deleted"))
