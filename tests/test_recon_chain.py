"""Cross-class chain todolist: templates, proven/ready/failed semantics, lineage."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.campaign import OutOfScope  # noqa: F401  (scope errors are StageError in findings)
from recon.chain import (ChainLedger, MAX_STEPS, NAME_RE, CLASS_RE, REALISM_QUESTIONS,
                         STEP_CHAINS, _templates, load_plan)
from recon.cli import main
from recon.findings import CHAIN_HINTS, Findings, RELATIONS
from recon.pipeline import Recon
from tests.test_recon import write_campaign


class ChainFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.fx = Findings(self.ctx)
        self.ledger = ChainLedger(self.ctx)

    def evidence(self, name, text):
        path = self.root / "ev" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def plan(self, name="custom-flow", steps=None):
        return {"name": name, "description": "operator chain",
                "steps": steps or [{"class": "idor-bola", "goal": "read victim export"},
                                   {"class": "info-disclosure", "goal": "capture PII"}]}

    def add_confirmed(self, bug_class, url="https://acme.test/x", title=None):
        fid, _ = self.fx.add(title or f"{bug_class} lead", bug_class, url=url)
        self.fx.move(fid, "confirmed",
                     replay=self.evidence(f"replay-{fid}", f"replay {fid} {bug_class}"),
                     control=self.evidence(f"control-{fid}", f"control {fid} {bug_class}"))
        return fid

    def chain(self, name):
        return next(c for c in self.ledger.overview()["chains"] if c["name"] == name)


class ChainTemplateTests(ChainFixture):
    def test_templates_are_well_formed_and_cover_every_hint(self):
        names = [name for name, _, _ in _templates()]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), len(STEP_CHAINS) + len(CHAIN_HINTS))
        for name, description, steps in _templates():
            self.assertRegex(name, NAME_RE.pattern)
            self.assertTrue(description)
            self.assertTrue(2 <= len(steps) <= MAX_STEPS)
            for cls, goal in steps:
                self.assertRegex(cls, CLASS_RE.pattern)
                self.assertTrue(goal)
        for a, b, _ in CHAIN_HINTS:
            self.assertIn(f"hint-{a}-{b}", names)

    def test_empty_campaign_frontier_is_ready_and_later_steps_wait(self):
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            overview = self.ledger.overview()
        chain = next(c for c in overview["chains"] if c["name"] == "redirect-oauth-ato")
        self.assertEqual(chain["state"], "ready")
        self.assertEqual([s["state"] for s in chain["steps"]], ["ready", "waiting", "waiting"])
        self.assertIn("hunt 'open-redirect'", chain["action"])
        self.assertFalse(overview["executed"])
        self.assertIn("replay + negative control", overview["basis"])

    def test_proven_steps_unlock_and_complete_the_chain(self):
        self.add_confirmed("idor-bola")
        chain = self.chain("hint-idor-bola-ato")
        self.assertEqual(chain["steps"][0]["state"], "proven")
        self.assertEqual(chain["steps"][1]["state"], "ready")
        self.assertEqual(chain["state"], "ready")
        self.assertIn("hunt 'ato'", chain["action"])
        self.add_confirmed("ato", url="https://acme.test/takeover")
        # All steps proven, but the realism gate parks the impact claim until
        # the three questions carry evidence-backed answers (plan §6).
        chain = self.chain("hint-idor-bola-ato")
        self.assertEqual(chain["state"], "parked")
        self.assertIn("realism gate is not satisfied", chain["action"])
        self.assertIn("reachable", chain["action"])
        self.assertFalse(chain["realism"]["complete"])
        for question, _ in REALISM_QUESTIONS:
            self.ledger.realism("hint-idor-bola-ato", question, "pass",
                                note="evidence in impact artifact")
        chain = self.chain("hint-idor-bola-ato")
        self.assertEqual(chain["state"], "complete")
        self.assertEqual(chain["proven_steps"], 2)
        self.assertIsNone(chain["next"])
        self.assertTrue(all(s["state"] == "proven" for s in chain["steps"]))
        self.assertTrue(chain["realism"]["complete"])

    def test_realism_fail_parks_with_the_failing_question_named(self):
        self.add_confirmed("idor-bola")
        self.add_confirmed("ato", url="https://acme.test/takeover")
        self.ledger.realism("hint-idor-bola-ato", "reachable", "pass", note="public surface")
        self.ledger.realism("hint-idor-bola-ato", "preconditions", "pass", note="token obtainable")
        self.ledger.realism("hint-idor-bola-ato", "downstream", "fail",
                            note="server-side authz on the chained object")
        chain = self.chain("hint-idor-bola-ato")
        self.assertEqual(chain["state"], "parked")
        self.assertIn("downstream", chain["action"])
        self.assertEqual(chain["realism"]["failed"], ["downstream"])
        with self.assertRaises(ValueError):
            self.ledger.realism("hint-idor-bola-ato", "nonsense", "pass")
        with self.assertRaises(ValueError):
            self.ledger.realism("hint-idor-bola-ato", "reachable", "maybe")

    def test_dead_pivot_parks_and_blocks_but_never_refutes_siblings(self):
        first = self.add_confirmed("open-redirect")
        dead, _ = self.fx.add("oauth lead", "oauth", url="https://acme.test/oauth")
        self.fx.move(dead, "killed", note="state is bound correctly")
        chain = self.chain("redirect-oauth-ato")
        self.assertEqual([s["state"] for s in chain["steps"]], ["proven", "failed", "blocked"])
        self.assertEqual(chain["state"], "parked")
        self.assertIn("dead", chain["action"])
        # A live sibling lead of the same class keeps the step actionable.
        sibling, _ = self.fx.add("oauth second lead", "oauth", url="https://acme.test/oauth2")
        chain = self.chain("redirect-oauth-ato")
        self.assertEqual(chain["steps"][1]["state"], "ready")
        self.assertEqual(chain["steps"][1]["lead_open"], [sibling])
        self.assertIn("confirm", chain["action"])

    def test_out_of_scope_findings_are_never_created(self):
        from recon.findings import StageError
        with self.assertRaises(StageError):
            self.fx.add("lead", "idor-bola", url="https://elsewhere.example/x")


class ChainLineageTests(ChainFixture):
    def test_lead_open_confirms_instead_of_rehunting(self):
        lead, _ = self.fx.add("idor on invoices", "idor-bola", url="https://acme.test/api/invoices")
        chain = self.chain("hint-idor-bola-ato")
        self.assertEqual(chain["steps"][0]["state"], "ready")
        self.assertEqual(chain["steps"][0]["lead_open"], [lead])
        self.assertIn(f"confirm open lead(s) [{lead}]", chain["action"])

    def test_lineage_relations_are_accepted_and_detected_between_proven_steps(self):
        for relation in ("spawns", "derived-from", "proves"):
            self.assertIn(relation, RELATIONS)
        idor = self.add_confirmed("idor-bola", url="https://acme.test/reset")
        ato = self.add_confirmed("ato", url="https://acme.test/takeover")
        chain = self.chain("hint-idor-bola-ato")
        self.assertFalse(chain["steps"][1]["linked_from_prev"])
        self.assertTrue(self.fx.link(idor, "spawns", ato, "reset object read spawns takeover"))
        chain = self.chain("hint-idor-bola-ato")
        self.assertTrue(chain["steps"][1]["linked_from_prev"])

    def test_findings_report_contains_the_todolist(self):
        from recon.findings import write_findings
        self.add_confirmed("idor-bola")
        path = write_findings(self.ctx)
        text = path.read_text()
        self.assertIn("Chain todolist", text)
        self.assertIn("hint-idor-bola-ato", text)
        self.assertIn("hunt 'ato'", text)


class ChainCustomTests(ChainFixture):
    def test_custom_chain_persists_and_resolves_like_templates(self):
        self.ledger.add("custom-flow", "operator chain", self.plan()["steps"])
        self.add_confirmed("idor-bola", url="https://acme.test/export")
        chain = self.chain("custom-flow")
        self.assertEqual(chain["description"], "operator chain")
        self.assertEqual([s["state"] for s in chain["steps"]], ["proven", "ready"])

    def test_invalid_custom_chains_fail_closed(self):
        bad = [
            self.plan(name="Bad Name"), self.plan(name="x"),
            self.plan(name="redirect-oauth-ato"),
            self.plan(steps=[{"class": "a"}]),
            self.plan(steps=[{"class": "xss", "goal": "g"}] * 2),
            self.plan(steps=[{"class": "xss", "goal": "g"}] * (MAX_STEPS + 1)),
            self.plan(steps=[{"class": "XSS", "goal": "g"}, {"class": "xss", "goal": "g"}]),
            self.plan(steps=[{"class": "xss", "goal": "g", "extra": 1},
                             {"class": "xss", "goal": "g"}]),
            self.plan(steps=[{"class": "xss", "goal": "x" * 201},
                             {"class": "xss", "goal": "g"}]),
        ]
        for plan in bad:
            with self.subTest(name=plan.get("name"), steps=len(plan.get("steps") or [])):
                self.assertRaises(ValueError, self.ledger.add,
                                  plan["name"], plan.get("description", ""), plan["steps"])
        self.ledger.add("custom-flow", "ok", self.plan()["steps"])
        with self.assertRaises(ValueError):
            self.ledger.add("custom-flow", "duplicate", self.plan()["steps"])


class ChainCLITests(ChainFixture):
    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                patch("socket.socket", side_effect=AssertionError("CLI must remain offline")):
            rc = main(["chain", *args, str(self.root)])
        return rc, out.getvalue(), err.getvalue()

    def test_status_and_add_are_offline(self):
        rc, text, _ = self.invoke("status")
        self.assertEqual(rc, 0)
        data = json.loads(text)
        self.assertGreater(len(data["chains"]), len(STEP_CHAINS))
        plan = self.root / "plan.json"
        plan.write_text(json.dumps(self.plan()))
        rc, text, _ = self.invoke("add", "--file", str(plan))
        self.assertEqual(rc, 0)
        self.assertIn("custom-flow", text)
        rc, text, _ = self.invoke("status")
        self.assertIn("custom-flow", text)

    def test_invalid_file_exits_nonzero(self):
        plan = self.root / "plan.json"
        plan.write_text('{"name": "bad name"}')
        self.assertEqual(self.invoke("add", "--file", str(plan))[0], 1)
        plan.write_text("{")
        self.assertRaises(json.JSONDecodeError, load_plan, plan)


if __name__ == "__main__":
    unittest.main()
