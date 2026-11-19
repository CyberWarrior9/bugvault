import ast
import csv
import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from recon.campaign import Scope
from recon.invariants import Model, evaluate, exact, money
from tests.invariant_fixtures import campaign, declaration


class InvariantModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ctx = campaign(Path(self.tmp.name) / "camp")
        self.addCleanup(self.ctx.store.close)
        self.model = Model(self.ctx)

    def test_empty_schema_idempotent_and_no_fabricated_capture(self):
        original = self.ctx.store.network_attempts()
        self.model.declare(declaration(contexts=False))
        self.assertEqual(self.model.sync_contexts(), {})
        self.assertEqual(self.model.contexts("coupon"), [])
        self.assertEqual(self.ctx.store.network_attempts(), original)
        self.assertEqual(Model(self.ctx).declare(declaration(contexts=False))["unchanged"], True)
        self.assertEqual(self.ctx.store.coverage(), [])
        self.ctx.store.db.execute("UPDATE invariant_meta SET value='99' WHERE key='schema_version'")
        self.ctx.store.db.commit()
        with self.assertRaisesRegex(ValueError, "newer"):
            Model(self.ctx)

    def test_schema_bounds_no_partial_write_or_code_execution(self):
        data = declaration()
        for change in ({"extra": "{{ 7*7 }}"}, {"schema": 2},
                       {"operations": [{"key": "x", "url": "file:///etc/passwd", "method": "GET"}]},
                       {"workflow": {**data["workflow"], "requires": [["claim", "redeem"],
                                                                  ["redeem", "claim"]]}}):
            bad = {**data, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.model.declare(bad)
            self.assertIsNone(self.model.workflow("coupon"))
        self.assertEqual(self.model.declare(data)["operations"], 2)

    def test_typed_money_and_authority(self):
        for value in (True, 0.1, "NaN", "Infinity", 10**18):
            with self.subTest(value=value), self.assertRaises(ValueError):
                exact(value, "value")
        self.assertEqual(exact("1.25", "value"), Decimal("1.25"))
        self.assertEqual(money({"currency": "USD", "amount": "1.25"}, "USD", 2, "amount"), 125)
        for bad in ({"currency": "EUR", "minor": 1}, {"currency": "USD", "amount": "0.001"},
                    {"currency": "USD", "minor": True}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                money(bad, "USD", 2, "amount")
        wf = {"states": ["new", "used"], "edges": [["new", "used"]]}
        self.assertEqual(evaluate({"type": "at-most-count", "limit": 1}, wf,
                                  {"effects": 2, "source": "ui"}, "declared")[0], "unknown")
        self.assertEqual(evaluate({"type": "at-most-count", "limit": 1}, wf,
                                  {"effects": 2}, "inferred-observed")[0], "unknown")
        self.assertEqual(evaluate({"type": "at-most-count", "limit": 1}, wf,
                                  {"effects": 2}, "declared")[0], "violated")

    def test_contexts_isolate_accounts_and_reimport(self):
        self.model.declare(declaration(contexts=False))
        eid = self.ctx.add_endpoint("http://127.0.0.1:12345/claim", "har", method="POST")
        for who in ("a", "v", None):
            key = f"capture-{who}"
            self.ctx.store.add_observation(eid, "POST", who, {"query": [], "body": ["coupon", "quantity"]},
                                           200, "har", capture_key=key,
                                           context={"role": "tester", "tenant": "owned", "session": key,
                                                    "workflow_state": "new"})
        stats = self.model.sync_contexts()
        self.assertEqual(stats["contexts_added"], 3)
        self.assertEqual(self.model.sync_contexts(), {})
        self.assertEqual(len(self.model.contexts("coupon")), 3)
        self.assertEqual(len({c["id"] for c in self.model.contexts("coupon")}), 3)

    def test_query_shape_does_not_attribute_a_different_operation(self):
        data = declaration(contexts=False)
        data["operations"][0]["url"] += "?campaign=owned"
        self.model.declare(data)
        eid = self.ctx.add_endpoint("http://127.0.0.1:12345/claim?other=value", "har", method="POST")
        self.ctx.store.add_observation(eid, "POST", "a", {"query": ["other"],
                                           "body": ["coupon", "quantity"]}, 200, "har",
                                       capture_key="wrong-query", context={"role": "tester",
                                                                           "tenant": "owned", "session": "sa"})
        self.assertEqual(self.model.sync_contexts(), {})
        self.assertEqual(self.model.contexts("coupon"), [])
        self.ctx.store.add_observation(eid, "POST", "a", {"query": ["campaign"],
                                           "body": ["coupon", "quantity"]}, 200, "har",
                                       capture_key="right-query", context={"role": "tester",
                                                                           "tenant": "owned", "session": "sa"})
        self.assertEqual(self.model.sync_contexts()["contexts_added"], 1)
        self.assertEqual(len(json.loads(self.model.contexts("coupon")[0]["observation_ids"])), 1)

    def test_current_scope_change_blocks_stored_operation(self):
        wf = self.model.declare(declaration())
        self.assertTrue(self.model.operations(wf["workflow_id"])[1]["in_scope"])
        self.ctx.scope = Scope.from_lists(["127.0.0.1"], ["/redeem"])
        self.ctx.policy.mode = "active"
        self.ctx.policy.allowed_methods = ["GET", "HEAD", "POST"]
        self.assertFalse(self.ctx.scope.is_in("http://127.0.0.1:12345/redeem"))
        self.assertEqual(self.model.sync_contexts(), {})
        wf, inv = self.model.current_invariant("coupon", "once")
        context = self.model.contexts("coupon")[0]
        state, reason = self.model.live_gate("logic", "BL-10", ("R", "L", "C-S"), context,
                                              wf, inv, self.model.operations(wf["id"]))
        self.assertEqual(state, "policy-blocked")
        self.assertIn("outside the recorded scope", reason)

    def test_offline_paths_do_not_open_connections(self):
        with patch("socket.socket", side_effect=AssertionError("network called")):
            self.model.declare(declaration())
            self.model.sync_contexts()
            self.assertEqual(self.model.verify()["verified"], True)

    def test_corpus_race_rule_is_exact_and_existing_indexes_are_not_rewritten(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "build_dossiers.py"
        tree = ast.parse(script.read_text())  # mapping check needs no parquet import
        rules = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == "W2C" for t in n.targets))
        for weakness in ("Time-of-check Time-of-use (TOCTOU) Race Condition",
                         "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
                         "Leveraging Race Conditions"):
            self.assertEqual(rules[weakness], "race-conditions")
        with (script.parents[1] / "vault" / "_data" / "reports-merged.csv").open() as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(sum(rules.get(r["weakness"]) == "race-conditions" for r in rows), 44)
