import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon.cli import main
from recon.logic import LogicLedger
from recon.report import write_reports
from recon.findings import Findings
from tests.invariant_fixtures import artifact, campaign, declaration, event


class LogicLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.ctx = campaign(self.root)
        self.addCleanup(self.ctx.store.close)
        self.logic = LogicLedger(self.ctx)
        self.logic.declare(declaration())
        self.a = next(c["id"] for c in self.logic.model.contexts("coupon") if c["account"] == "a")

    def test_probe_is_bounded_and_sequence_survivor_escalates_without_send(self):
        with patch("socket.socket", side_effect=AssertionError("network called")):
            sweep = self.logic.probe("coupon", 4)
            self.assertEqual(len(sweep["cards"]), 4)
            self.assertTrue(sweep["truncated"])
            self.assertFalse(sweep["executed"])
            self.assertNotIn("payload", sweep["cards"][0])
            neg = event(self.root, self.a, "negative_mark_00001", outcome="negative-for-variant",
                        count=1, suffix="neg")
            neg.update({"note": "atomic consumption refused a second owned attempt", "impact_tier": "T0"})
            result = self.logic.record(neg)
            self.assertIsNotNone(result["race_candidate_scenario"])
            self.assertIsNone(self.logic.record({**neg, "marker": "negative_mark_00002", "control": "unknown",
                                                "artifacts": event(self.root, self.a, "negative_mark_00002",
                                                                   suffix="neg2")["artifacts"]})
                             .get("race_candidate_scenario"))
            self.assertEqual(self.logic.model.chain_next(), [])

    def test_anomaly_inferred_lead_without_rule_never_becomes_observed(self):
        inferred = declaration(policy="inferred-observed")
        inferred["workflow"]["revision"] = 2
        self.logic.declare(inferred)
        baseline = artifact(self.root, "baseline.txt", "owned valid response 200")
        attempted = artifact(self.root, "attempt.txt", "owned variant response 202")
        oracle = artifact(self.root, "observed.txt", "owned state unchanged")
        result = self.logic.observe({"context": self.a, "operation": "claim", "dimension": "quantity",
                                     "variant": "negative", "suspected_rule": "quantity must be positive",
                                     "baseline": baseline, "attempt": attempted, "oracle": oracle, "tier": "T1"})
        self.assertEqual(result["policy_status"], "inferred-observed")
        self.assertEqual(result["verdict"], "unadjudicated lead")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.logic.record(event(self.root, self.a, "inferred_mark_00001"))
        self.assertFalse(self.logic.close(result["observation_id"], "owner rule unresolved")["promoted"])
        self.assertTrue(self.logic.verify()["verified"])
        self.assertFalse(self.logic.status()["finding_promoted"])

    def test_observed_requires_controls_and_verify_rehashes_history(self):
        first = event(self.root, self.a, "logic_trial_000001", suffix="first")
        with self.assertRaisesRegex(ValueError, "control"):
            self.logic.record({**first, "control_projections": None})
        with self.assertRaisesRegex(ValueError, "oracle"):
            self.logic.record({**first, "artifacts": first["artifacts"][:2]})
        got = self.logic.record(first)
        self.assertEqual(got["verdict"], "violated")
        self.assertEqual(got["impact_tier"], "T1")
        self.assertTrue(got["lab_only"])
        self.assertEqual(self.logic.status()["events"][0]["readiness"], "lab-only-review")
        with self.assertRaisesRegex(ValueError, "recycled"):
            self.logic.record(first)
        self.assertTrue(self.logic.verify()["verified"])
        path = self.ctx.store.db.execute("SELECT path FROM workflow_artifacts WHERE event_id=? AND role='oracle'",
                                         (got["event_id"],)).fetchone()[0]
        (self.root / path).write_text("changed historical evidence")
        self.assertFalse(self.logic.verify()["verified"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["logic", "verify", str(self.root)]), 2)

    def test_terminal_one_field_write_and_cleanup(self):
        marker = "owned_write_000001"
        env = event(self.root, self.a, marker, suffix="term")
        env["impact_tier"] = "T2"
        env["terminal"] = {"kind": "owned-write", "object": env["object_ref"], "field": "entitlement",
                           "before": "none", "after": "granted"}
        env["artifacts"] += [
            "owned-write=" + artifact(self.root, "write.txt", env["object_ref"] + " entitlement granted"),
            "readback=" + artifact(self.root, "readback.txt", env["object_ref"] + " entitlement granted")]
        result = self.logic.record(env)
        self.assertEqual(result["impact_tier"], "T2")
        self.assertEqual(len(self.logic.model.obligations()), 1)
        receipt = artifact(self.root, "cleanup.txt", marker + " deleted owned fixture")
        self.assertTrue(self.logic.model.cleanup(result["event_id"], "deleted", receipt)["resolved"])
        self.assertEqual(self.logic.model.obligations(), [])
        self.assertTrue(self.logic.verify()["verified"])

    def test_one_owned_sensitive_field_read_has_independent_ui_control(self):
        env = event(self.root, self.a, "owned_read_0000001", suffix="read")
        env["impact_tier"] = "T3"
        env["terminal"] = {"kind": "victim-read", "account": "a", "field": "email", "records": 1}
        env["artifacts"] += ["victim-read=" + artifact(self.root, "victim.txt", "server email field only"),
                             "redacted=" + artifact(self.root, "redacted.txt", "email: [redacted]"),
                             "ui-control=" + artifact(self.root, "ui.txt", "owned UI absent sensitive field")]
        self.assertEqual(self.logic.record(env)["impact_tier"], "T3")
        another = event(self.root, self.a, "owned_read_0000002", suffix="readbad")
        with self.assertRaisesRegex(ValueError, "operator's own"):
            self.logic.record({**env, "marker": another["marker"],
                               "control_marker": another["control_marker"],
                               "artifacts": another["artifacts"] + env["artifacts"][4:],
                               "terminal": {**env["terminal"], "account": "outsider"}})

    def test_lineage_hints_reject_unrelated_findings_and_t4_needs_lab_rehearsal(self):
        env = event(self.root, self.a, "lineage_case_00001", suffix="lineage")
        first = self.logic.record(env)
        hints = self.logic.model.chain_next()
        p1 = next(h for h in hints if h["hint"] == "business-logic->access-control")
        self.assertEqual(p1["play"], "P1-entitlement-action")
        self.assertIsNone(p1["target_finding"])
        finding = Findings(self.ctx)
        fid, _ = finding.add("synthetic reserved action", "access-control",
                             url="http://127.0.0.1:12345/claim", detail={"lineage": ["root:unrelated"]})
        proof = self.root / artifact(self.root, "proof.txt", "owned synthetic action")
        control = self.root / artifact(self.root, "proof-control.txt", "fixed synthetic refusal")
        impact = self.root / artifact(self.root, "impact.txt", "owned synthetic action effect")
        finding.move(fid, "confirmed", replay=proof, control=control)
        finding.move(fid, "impact-proven", impact=impact, poe_level=3,
                     quote="owned synthetic action effect", impact_kind="state-change",
                     measurement="1 of 1 owned synthetic actions took effect")
        self.assertIsNone(next(h for h in self.logic.model.chain_next()
                               if h["hint"] == "business-logic->access-control")["target_finding"])
        # Test-only change of the synthetic finding's explicit lineage, not a claim about a target.
        lineage = first["lineage"]
        self.ctx.store.db.execute("UPDATE findings SET detail=? WHERE id=?",
                                  (json.dumps({"lineage": lineage}), fid))
        self.ctx.store.db.commit()
        linked = next(h for h in self.logic.model.chain_next() if h["hint"] == "business-logic->access-control")
        self.assertEqual(linked["target_finding"], fid)
        second = event(self.root, self.a, "lineage_case_00002", suffix="lineage2")
        second.update({"impact_tier": "T4", "chain_finding": fid})
        self.assertEqual(self.logic.record(second)["impact_tier"], "T1")
        third = event(self.root, self.a, "lineage_case_00003", suffix="lineage3")
        third.update({"impact_tier": "T4", "chain_finding": fid})
        third["artifacts"] += ["lab-rehearsal=" + artifact(self.root, "rehearsal.txt",
                                                           "owned synthetic entitlement to reserved action")]
        self.assertEqual(self.logic.record(third)["impact_tier"], "T4")

    def test_coarse_status_report_does_not_close_exact_case(self):
        endpoint = self.ctx.add_endpoint("http://127.0.0.1:12345/claim", "har", method="POST")
        self.ctx.store.set_coverage(endpoint, "business-logic", "tested", "coarse only")
        paths = write_reports(self.ctx)
        report = (self.root / "coverage.md").read_text()
        self.assertIn("Business-invariant and race evidence", report)
        self.assertIn("Coarse BL/race statuses cannot close open exact cases", report)
        self.assertTrue(any(p.name == "coverage.md" for p in paths))

    def test_cli_declare_probe_plan_status_offline(self):
        for args in (["logic", "probe", str(self.root), "--workflow", "coupon", "--limit", "2"],
                     ["logic", "plan", str(self.root)], ["race", "sync", str(self.root)],
                     ["race", "status", str(self.root)]):
            with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(args), 0)
                self.assertFalse(json.loads(out.getvalue())["executed"])

    def test_lab_only_family_plan_matches_record_gate(self):
        revised = declaration(family="BL-06")
        revised["workflow"]["revision"] = 2
        self.logic.declare(revised)
        rows = self.logic.plan()["rows"]
        self.assertTrue(rows)
        self.assertTrue(all(r["readiness"] == "lab-only" for r in rows))
