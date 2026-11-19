"""Adversarial Gate A additions; all evidence is synthetic and offline/owned lab."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon.invariants import Model, evaluate, money, parse_declaration, read_json_file
from recon.logic import LogicLedger
from recon.race import RaceLedger
from tests.invariant_fixtures import artifact, campaign, declaration, event
from tests.test_recon_race import run, scenario


class OfflineGateA(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "camp"
        self.ctx = campaign(self.root)
        self.addCleanup(self.ctx.store.close)
        self.logic = LogicLedger(self.ctx)

    def test_a01_legacy_reopen_is_additive_and_future_schema_fails_before_write(self):
        eid = self.ctx.add_endpoint("http://127.0.0.1:12345/claim", "har", method="POST")
        self.ctx.store.set_coverage(eid, "business-logic", "tested", "historical status")
        original = self.ctx.store.coverage()
        self.logic.model.db.execute("DROP TABLE invariant_meta")
        self.logic.model.db.commit()
        Model(self.ctx)
        Model(self.ctx)
        self.assertEqual(self.ctx.store.coverage(), original)
        self.assertEqual(self.logic.model.contexts("coupon"), [])
        self.logic.model.db.execute("UPDATE invariant_meta SET value='100' WHERE key='schema_version'")
        self.logic.model.db.commit()
        with self.assertRaisesRegex(ValueError, "newer"):
            Model(self.ctx)
        self.assertEqual(self.ctx.store.coverage(), original)

    def test_a02_exact_identity_and_unknown_capture_separation(self):
        data = declaration(contexts=False)
        first = data["operations"][0]
        variants = (
            ("method", "PUT"), ("url", "http://127.0.0.1:12346/claim"),
            ("url", "http://127.0.0.1:12345/Claim"),
            ("url", "http://127.0.0.1:12345/claim?shape=x"),
            ("selector", "mutation Claim"), ("fields", ["other"]),
            ("version", "v2"), ("representation", "application/json"),
        )
        shapes = set()
        for key, value in variants:
            changed = {**first, key: value}
            altered = {**data, "operations": [changed, data["operations"][1]]}
            shapes.add(parse_declaration(altered, self.ctx.scope)["operations"][0]["shape_sha"])
        self.assertEqual(len(shapes), len(variants))
        self.logic.declare(data)
        eid = self.ctx.add_endpoint(first["url"], "har", method="POST")
        for i in range(2):
            self.ctx.store.add_observation(eid, "POST", None, {"query": [], "body": first["fields"]},
                                           200, "har", capture_key=f"unknown-{i}", context={})
        self.assertEqual(self.logic.model.sync_contexts()["contexts_added"], 2)
        self.assertEqual(self.logic.model.sync_contexts(), {})

    def test_a03_import_and_paths_fail_without_partial_event_or_execution(self):
        self.logic.declare(declaration())
        account = self.logic.model.contexts("coupon")[0]["id"]
        bad = declaration()
        bad["workflow"]["states"] = [["not", "hashable"]]
        with self.assertRaises(ValueError):
            parse_declaration(bad, self.ctx.scope)
        cyclic = []
        cyclic.append(cyclic)
        bad = declaration()
        bad["workflow"]["states"] = cyclic
        with self.assertRaises(ValueError):
            parse_declaration(bad, self.ctx.scope)
        large = self.root / "large.json"
        large.write_bytes(b" " * (1_048_576 + 1))
        with self.assertRaisesRegex(ValueError, "mebibyte"):
            read_json_file(large)
        outside = self.root.parent / "outside.txt"
        outside.write_text("owned")
        (self.root / "link.txt").symlink_to(outside)
        for path in ("../outside.txt", "link.txt"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.logic.record({**event(self.root, account, "bad_path_marker_01"),
                                   "artifacts": [f"oracle={path}"]})
        with patch("socket.socket", side_effect=AssertionError("network called")), \
                patch("subprocess.Popen", side_effect=AssertionError("command called")):
            with self.assertRaises(ValueError):
                self.logic.record({**event(self.root, account, "bad_input_marker_1"),
                                   "note": "$(touch /somewhere)", "unexpected": "{{7*7}}"})
        self.assertEqual(self.logic.status()["event_total"], 0)

    def test_a04_a05_exact_predicates_and_ordered_graph(self):
        wf = {"states": ["new", "approved", "cancelled", "refunded"],
              "edges": [["new", "approved"], ["approved", "cancelled"]]}
        cases = [
            ({"type": "allowed-transition"}, {"from": "new", "to": "approved"}, "satisfied"),
            ({"type": "allowed-transition"}, {"from": "new", "to": "refunded"}, "violated"),
            ({"type": "prerequisite-before-effect", "prerequisite": "approve", "effect": "use"},
             {"sequence": ["use", "approve"]}, "violated"),
            ({"type": "prerequisite-before-effect", "prerequisite": "approve", "effect": "use"},
             {"sequence": ["approve", "use"]}, "satisfied"),
            ({"type": "version-current-at-effect"}, {"checked_version": 1, "effect_version": 2}, "violated"),
            ({"type": "refund-capacity", "currency": "USD", "exponent": 2},
             {"captured": {"currency": "USD", "amount": "1.25"},
              "refunds": [{"currency": "USD", "minor": 75}, {"currency": "USD", "minor": 75}]}, "violated"),
        ]
        for rule, projections, expected in cases:
            with self.subTest(rule=rule, projections=projections):
                self.assertEqual(evaluate(rule, wf, projections, "declared")[0], expected)
                self.assertEqual(evaluate(rule, wf, projections, "unknown")[0], "unknown")
        self.assertEqual(money({"currency": "JPY", "amount": "2"}, "JPY", 0, "price"), 2)
        for amount in ("0.01", "NaN", 1.5, True):
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                money({"currency": "JPY", "amount": amount}, "JPY", 0, "price")

    def test_a06_inferred_observation_does_not_adjudicate_or_grant_live_readiness(self):
        data = declaration(policy="inferred-observed")
        self.logic.declare(data)
        ctx = self.logic.model.contexts("coupon")[0]["id"]
        observation = self.logic.observe({"context": ctx, "operation": "claim", "dimension": "quantity",
                                          "variant": "negative", "suspected_rule": "positive only",
                                          "baseline": artifact(self.root, "a.txt", "valid owned path"),
                                          "attempt": artifact(self.root, "b.txt", "different owned path")})
        self.assertEqual(observation["verdict"], "unadjudicated lead")
        self.assertEqual(self.logic.plan()["rows"][0]["readiness"], "policy-blocked")
        with self.assertRaisesRegex(ValueError, "unresolved"):
            self.logic.record(event(self.root, ctx, "inferred_case_001", suffix="inferred"))

    def test_a07_a08_source_provenance_and_recycled_artifacts(self):
        self.logic.declare(declaration())
        ctx = self.logic.model.contexts("coupon")[0]["id"]
        uri = "http://127.0.0.1:12345/claim"
        rid = self.ctx.store.record_request("POST", uri, None, "synthetic-error", [], {},
                                           basis="imported-burp-capture", error="transport error")
        with self.assertRaisesRegex(ValueError, "not target-http"):
            self.logic.model.receipts([{"basis": "target-http", "request_id": rid}], "native",
                                      self.logic.model.operations(self.logic.model.workflow("coupon")["id"]),
                                      self.logic.model.context(ctx), "")
        with self.assertRaisesRegex(ValueError, "does not exist"):
            self.logic.model.receipts([{"basis": "owned-loopback", "request_id": 999999}], "lab",
                                      self.logic.model.operations(self.logic.model.workflow("coupon")["id"]),
                                      self.logic.model.context(ctx), "")
        self.assertEqual(self.logic.model.usage()["native_measured"], 0)
        env = event(self.root, ctx, "fresh_causal_marker1", suffix="causal")
        with self.assertRaisesRegex(ValueError, "control marker"):
            self.logic.record({**env, "control_marker": env["marker"]})
        self.assertEqual(self.logic.record(env)["verdict"], "violated")
        with self.assertRaisesRegex(ValueError, "recycled"):
            self.logic.record(env)

    def test_a07_a09_error_reply_needs_owner_commit_trace_not_client_timing(self):
        self.logic.declare(declaration())
        ctx = self.logic.model.contexts("coupon")[0]["id"]
        marker = "unknown_delivery_owned01"
        rid = self.ctx.store.record_request(
            "POST", "http://127.0.0.1:12345/claim", None, "owned timed-out response", [], {},
            basis="owned-loopback", error="timeout", req_body=marker.encode(),
            req_content_type="text/plain")
        env = event(self.root, ctx, marker, suffix="unknown-delivery")
        env["receipts"] = [{"basis": "owned-loopback", "request_id": rid}]
        with self.assertRaisesRegex(ValueError, "unknown delivery"):
            self.logic.record(env)
        env["artifacts"] += ["commit-trace=" + artifact(self.root, "commit-trace.txt",
                              "owner commit sequence 12, marker " + marker)]
        self.assertEqual(self.logic.record(env)["verdict"], "violated")
        self.assertEqual(self.logic.model.usage()["lab"], 1)
        # A 5xx captured status cannot silently bypass the stop merely by omitting
        # the optional response_status field from the event envelope.
        rid2 = self.ctx.store.record_request("POST", "http://127.0.0.1:12345/claim", 503,
                                             "synthetic", [], {}, basis="owned-loopback")
        blocked = {"context": ctx, "invariant": "once", "case": "BL-10", "outcome": "blocked",
                   "impact_tier": "T0", "note": "owned service unavailable",
                   "receipts": [{"basis": "owned-loopback", "request_id": rid2}]}
        with self.assertRaisesRegex(ValueError, "5xx"):
            self.logic.record(blocked)
        blocked["stop_trigger"] = "server-error"
        self.assertEqual(self.logic.record(blocked)["stopped_host"], "127.0.0.1")

    def test_a11_a13_pending_and_stops_are_ledger_only(self):
        self.logic.declare(declaration())
        ctx = self.logic.model.contexts("coupon")[0]["id"]
        pending = {"context": ctx, "invariant": "once", "case": "BL-10", "outcome": "pending",
                   "impact_tier": "T0", "facts": {"queued": "yes", "effected": "unknown"},
                   "marker": "queued_owned_marker01", "objects": 1, "object_ref": "pending-owned"}
        got = self.logic.record(pending)
        self.assertEqual(got["verdict"], "unknown")
        self.assertEqual(self.logic.model.obligations()[1]["kind"], "unknown-effect")
        self.logic.model.cleanup(got["event_id"], "failed", note="await owner state")
        self.assertTrue(self.logic.model.stops())
        with self.assertRaisesRegex(ValueError, "unknown effect"):
            self.logic.model.resume("127.0.0.1", "pending needs reconciliation")
        self.assertIn("cannot intercept", self.logic.model.usage()["basis"])

    def test_a19_a20_measurement_and_window_evidence(self):
        self.logic.declare(declaration())
        ctx = self.logic.model.contexts("coupon")[0]["id"]
        race = RaceLedger(self.ctx)
        sid = race.declare(scenario(ctx))["scenario_id"]
        base = run(sid, ctx)
        for bad in ({**base, "attempts": 2}, {**base, "parallelism": 3, "attempts": 3,
                     "successes": 0}, {**base, "stop_when_success": True}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                race.record(bad)
        with self.assertRaisesRegex(ValueError, "window-evidence"):
            race.record({**base, "parallelism": 2, "attempts": 2, "successes": 0,
                         "outcome": "negative-for-variant", "control": "serialization",
                         "note": "constraint blocked second writer"})

    def test_a12_reopening_only_changed_context_and_stale_points_not_aggregated(self):
        self.logic.declare(declaration(contexts=False))
        url = "http://127.0.0.1:12345/claim"
        eid = self.ctx.add_endpoint(url, "har", method="POST")
        for acct in ("a", "v"):
            self.ctx.store.add_observation(eid, "POST", acct, {"query": [], "body": ["coupon", "quantity"]},
                                           200, "har", capture_key="owned-" + acct,
                                           context={"role": "tester", "tenant": "owned", "session": acct})
        self.logic.model.sync_contexts()
        contexts = {c["account"]: c["id"] for c in self.logic.model.contexts("coupon")}
        a = self.logic.record(event(self.root, contexts["a"], "a_context_marker_01", suffix="ctxa"))
        v = self.logic.record(event(self.root, contexts["v"], "v_context_marker_01", suffix="ctxv"))
        self.assertTrue(self.logic.verify()["verified"])
        self.ctx.store.add_observation(eid, "POST", "a", {"query": [], "body": ["coupon", "quantity"]},
                                       201, "har", capture_key="new-owned-a",
                                       context={"role": "tester", "tenant": "owned", "session": "a"})
        self.logic.model.sync_contexts()
        rows = {r["id"]: self.logic.model.event_state(dict(r))[0] for r in self.logic.db.execute(
            "SELECT * FROM workflow_events")}
        self.assertEqual(rows[a["event_id"]], "stale")
        self.assertEqual(rows[v["event_id"]], "observed")
        self.assertTrue(self.logic.verify()["verified"])  # stale history is retained, not tampered
        stored = self.logic.db.execute("SELECT path FROM workflow_artifacts WHERE event_id=? AND role='after'",
                                       (v["event_id"],)).fetchone()[0]
        (self.root / stored).write_text("tampered")
        self.assertFalse(self.logic.verify()["verified"])

    def test_a22_race_t4_requires_race_lineage_not_logic_class(self):
        self.logic.declare(declaration())
        ctx = self.logic.model.contexts("coupon")[0]["id"]
        wf, inv = self.logic.model.current_invariant("coupon", "once")
        lineage = self.logic.model.lineage("coupon", inv, "same-root")
        with patch.object(self.logic.model, "_has_findings", return_value=False):
            tier, _, why = self.logic.model.impact(
                "T4", None, "observed", "violated", self.logic.model.context(ctx), wf, inv,
                {"oracle": b"owned", "lab-rehearsal": b"owned"}, "lab", "race", "owned-object",
                123, lineage, "synthetic account gain")
        self.assertEqual(tier, "T1")
        self.assertIn("target class", why[0])
        sid = RaceLedger(self.ctx).declare(scenario(ctx))["scenario_id"]
        with self.assertRaisesRegex(ValueError, "unresolved schedule causality"):
            RaceLedger(self.ctx).record({**run(sid, ctx), "impact_tier": "T4"})

    def test_a21_value_delta_cannot_borrow_another_objects_ledger(self):
        self.logic.declare(declaration())
        ctx = self.logic.model.contexts("coupon")[0]["id"]
        wf, inv = self.logic.model.current_invariant("coupon", "once")
        terminal = {"kind": "value-delta", "currency": "USD", "exponent": 2,
                    "minor": 10, "cap_minor": 10, "synthetic": True}
        tier, _, reasons = self.logic.model.impact(
            "T2", terminal, "observed", "violated", self.logic.model.context(ctx), wf, inv,
            {"oracle": b"owned", "value-delta": b"other account/object: 10"}, "lab", "logic",
            "expected-owned-object", None, [], "one bounded owned credit")
        self.assertEqual(tier, "T1")
        self.assertIn("owned object", reasons[0])
