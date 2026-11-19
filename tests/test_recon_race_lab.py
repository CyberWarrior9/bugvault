"""Deterministic owned-loopback collision: no target, sleeps, scanner or random retries."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

from recon.findings import Findings
from recon.race import RaceLedger
from tests.invariant_fixtures import artifact, campaign, declaration
from tests.owned_workflow_lab import OwnedCommerce
from tests.test_recon_race import scenario


class OwnedSlot:
    def __init__(self):
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                raw = self.rfile.read(length)
                request = json.loads(raw)
                marker = request["marker"]
                slot = request.get("slot", "shared")
                intent = request.get("intent", marker)
                if self.path not in ("/claim", "/redeem", "/batch", "/graphql") or \
                        not marker.startswith("member_"):
                    self.send_error(400)
                    return
                with owner.lock:
                    if intent in owner.intents and owner.mode == "fixed":
                        response = json.dumps({"member": marker, "accepted": True, "replayed": True}).encode()
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(response)))
                        self.end_headers()
                        self.wfile.write(response)
                        return
                if owner.mode == "vulnerable":
                    with owner.lock:
                        allowed = owner.counts.get(slot, 0) == 0
                        owner.trace.append(f"checked:{marker}:{slot}:{owner.counts.get(slot, 0)}")
                    if owner.barrier:
                        owner.barrier.wait(timeout=5)
                    if allowed:
                        with owner.lock:
                            owner.count += 1
                            owner.counts[slot] = owner.counts.get(slot, 0) + 1
                            owner.intents.add(intent)
                            owner.trace.append(f"effect:{marker}:{slot}:{owner.count}")
                else:
                    if owner.barrier:
                        with owner.lock:
                            owner.trace.append(f"arrived:{marker}:{owner.count}")
                        owner.barrier.wait(timeout=5)
                    with owner.lock:
                        allowed = owner.counts.get(slot, 0) == 0
                        if allowed:
                            owner.count += 1
                            owner.counts[slot] = owner.counts.get(slot, 0) + 1
                            owner.intents.add(intent)
                            owner.trace.append(f"effect:{marker}:{owner.count}")
                response = json.dumps({"member": marker, "accepted": allowed}).encode()
                self.send_response(200 if allowed else 409)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.lock = threading.Lock()
        self.count = 0
        self.counts = {}
        self.intents = set()
        self.mode = "vulnerable"
        self.barrier = None
        self.trace = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def reset(self, mode="vulnerable", concurrent=False):
        self.mode, self.count, self.trace = mode, 0, []
        self.counts, self.intents = {}, set()
        parties = 2 if concurrent is True else concurrent
        self.barrier = threading.Barrier(parties, timeout=5) if parties else None

    def hit(self, op, marker, *, slot="shared", intent=None):
        # Hard-coded 127.0.0.1 and this listener's ephemeral port; no redirect/proxy/fallback.
        raw = json.dumps({"marker": marker, "slot": slot, "intent": intent or marker}).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("POST", "/" + op, body=raw, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            return op, marker, response.status, response.read(), raw
        finally:
            conn.close()

    def exercise(self, tag, *, mode="vulnerable", concurrent=False, reverse=False):
        self.reset(mode, concurrent)
        ops = ("redeem", "claim") if reverse else ("claim", "redeem")
        markers = [f"member_{tag}_{i:02d}_00000001" for i in range(2)]
        if concurrent:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self.hit, op, m) for op, m in zip(ops, markers)]
                return [f.result(timeout=7) for f in futures]
        return [self.hit(op, m) for op, m in zip(ops, markers)]

    def group(self, tag, ops, *, mode="vulnerable"):
        if not 2 <= len(ops) <= 8 or len(set(ops)) != len(ops):
            raise ValueError("bounded distinct writers only")
        self.reset(mode, len(ops))
        with ThreadPoolExecutor(max_workers=len(ops)) as pool:
            futures = [pool.submit(self.hit, op, f"member_{tag}_{i:02d}_00000001")
                       for i, op in enumerate(ops)]
            return [future.result(timeout=7) for future in futures]


class DeterministicLoopbackRaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.lab = OwnedSlot()
        self.lab.__enter__()
        self.addCleanup(self.lab.__exit__, None, None, None)
        self.ctx = campaign(self.root)
        self.addCleanup(self.ctx.store.close)
        self.race = RaceLedger(self.ctx)
        self.race.model.declare(declaration(self.lab.port))
        self.a = self.race.model.contexts("coupon")[0]["id"]
        self.sid = self.race.declare(scenario(self.a))["scenario_id"]

    def receipt_members(self, results, *, tag, intents=None):
        per_op = {}
        for op, marker, status, body, raw in results:
            rid = self.ctx.store.record_request("POST", f"http://127.0.0.1:{self.lab.port}/{op}",
                                               status, "owned-loopback-fixture", [], {}, body=body,
                                               body_complete=True, basis="owned-loopback",
                                               context={"account": "a", "role": "tester", "tenant": "owned",
                                                        "session": "sa"}, req_body=raw,
                                               req_content_type="application/json")
            per_op[op] = (rid, marker)
        members = [{"operation": op, "context": self.a, "intent": intent,
                     "request_id": per_op[op][0], "marker": per_op[op][1]}
                   for op, intent in (intents or (("claim", "first"), ("redeem", "second")))]
        receipts = [{"basis": "owned-loopback", "request_id": m["request_id"]} for m in members]
        return members, receipts

    def lab_event(self, tag, results, schedule, outcome, *, replay_of=None, intents=None):
        members, receipts = self.receipt_members(results, tag=tag, intents=intents)
        marker = f"group_{tag}_00000001"
        control = "ctrl_" + hashlib.sha256(marker.encode()).hexdigest()[:20]
        count = self.lab.count
        before = artifact(self.root, f"before_{tag}.txt", "owned count 0 " + marker)
        after = artifact(self.root, f"after_{tag}.txt", f"owned count {count} {marker}")
        oracle = artifact(self.root, f"oracle_{tag}.txt", f"authoritative count {count} {marker}")
        ctrl = artifact(self.root, f"control_{tag}.txt", "owned control count 1 " + control)
        trace = artifact(self.root, f"trace_{tag}.txt", "\n".join(self.lab.trace) + " barrier release")
        env = {"scenario": self.sid, "schedule": schedule, "outcome": outcome,
               "impact_tier": "T1" if outcome == "observed" else "T0",
               "marker": marker, "control_marker": control, "control": "atomicity",
               "attacker_gain": "one extra synthetic owned entitlement" if outcome == "observed" else
                                "no additional owned effect",
               "next_play": "P1-entitlement-action",
               "members": members, "receipts": receipts, "objects": 1 if outcome == "observed" else 0,
               "object_ref": "fixture-" + tag, "projections": {"effects": count},
               "control_projections": {"effects": 1}, "baseline_projections": {"effects": 1},
               "artifacts": ["before=" + before, "after=" + after, "oracle=" + oracle,
                             "control=" + ctrl, "barrier-trace=" + trace],
               "timing_quality": "lab-monotonic" if schedule in ("concurrent", "fixed", "replay") else "unknown"}
        if outcome == "negative-for-variant":
            env["note"] = "atomicity refused the second owned attempt"
        if schedule in ("concurrent", "fixed", "replay"):
            env.update({"parallelism": len(members), "attempts": len(members),
                        "successes": max(0, count - 1) if outcome == "observed" else 0})
        if replay_of:
            env.update({"parent": replay_of, "kind": "replay"})
        return env

    def test_vulnerable_fixed_serial_replay_and_cleanup(self):
        # Both serial orders are contract-safe; neither response ordering nor 200 alone is proof.
        for name, reverse in (("serial-ab", False), ("serial-ba", True)):
            results = self.lab.exercise(name.replace("-", ""), reverse=reverse)
            self.assertEqual(self.lab.count, 1)
            self.assertEqual(sum(status == 200 for _, _, status, _, _ in results), 1)
            self.race.record(self.lab_event(name.replace("-", ""), results, name,
                                            "negative-for-variant"))
        vulnerable = self.lab.exercise("vuln", concurrent=True)
        self.assertEqual(self.lab.count, 2)
        trial = self.race.record(self.lab_event("vuln", vulnerable, "concurrent", "observed"))
        self.assertEqual(trial["verdict"], "violated")
        self.assertEqual(trial["success_ratio"], "1/2")
        self.assertTrue(trial["sync_evidenced"])
        self.assertIn("causality unresolved", trial["causality"])
        fixed = self.lab.exercise("fixed", mode="fixed", concurrent=True)
        self.assertEqual(self.lab.count, 1)
        self.race.record(self.lab_event("fixed", fixed, "fixed", "negative-for-variant"))
        replay = self.lab.exercise("replay", concurrent=True)
        self.assertEqual(self.lab.count, 2)
        replay_event = self.lab_event("replay", replay, "replay", "observed",
                                      replay_of=trial["event_id"])
        last = self.race.record(replay_event)
        self.assertIn("race-eligible for human validation", last["causality"])
        for tag in ("holdone", "holdtwo"):
            held = self.lab.exercise(tag, mode="fixed", concurrent=True)
            self.assertEqual(self.lab.count, 1)
            self.race.record(self.lab_event(tag, held, "fixed", "negative-for-variant"))
        with self.assertRaisesRegex(ValueError, "bound exceeded"):
            self.race.record(replay_event)
        self.assertTrue(last["lab_only"])
        self.assertFalse(last["finding_promoted"])
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        self.assertEqual(self.race.status()["run_total"], 7)
        self.assertEqual(self.race.status()["scenarios"][0]["points"][0]["ratio"], "1/2")
        self.assertTrue(self.race.verify()["verified"])
        for entry in (trial, last):
            name = f"cleanup-{entry['event_id']}.txt"
            marker = self.ctx.store.db.execute("SELECT marker FROM workflow_events WHERE id=?",
                                                (entry["event_id"],)).fetchone()[0]
            receipt = artifact(self.root, name, "deleted owned fixture " + marker)
            self.race.model.cleanup(entry["event_id"], "deleted", receipt)
        self.assertEqual(self.race.model.obligations(), [])
        self.assertTrue(self.race.verify()["verified"])

    def test_b01_disjoint_resource_and_same_key_replay_are_distinct_controls(self):
        self.lab.reset("vulnerable", concurrent=True)
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(self.lab.hit, "claim", "member_disjoint_a_00001", slot="slot-a")
            b = pool.submit(self.lab.hit, "redeem", "member_disjoint_b_00001", slot="slot-b")
            self.assertEqual([a.result(timeout=7)[2], b.result(timeout=7)[2]], [200, 200])
        self.assertEqual(self.lab.counts, {"slot-a": 1, "slot-b": 1})
        self.lab.reset("fixed")
        first = self.lab.hit("claim", "member_replay_first_00001", intent="same-intent")
        second = self.lab.hit("claim", "member_replay_again_00001", intent="same-intent")
        self.assertEqual([first[2], second[2]], [200, 200])
        self.assertTrue(json.loads(second[3])["replayed"])
        self.assertEqual(self.lab.counts, {"shared": 1})

    def test_b13_b15_bounded_four_writer_loopback_receipts_and_denominators(self):
        data = declaration(self.lab.port)
        data["workflow"]["key"] = "quota4"
        data["operations"] += [
            {"key": op, "url": f"http://127.0.0.1:{self.lab.port}/{op}", "method": "POST",
             "writes": ["slot"]} for op in ("batch", "graphql")]
        self.race.model.declare(data)
        self.a = self.race.model.contexts("quota4")[0]["id"]
        intents = [("claim", "first"), ("redeem", "second"), ("batch", "third"),
                   ("graphql", "fourth")]
        self.sid = self.race.declare({"schema": 1, "workflow": "quota4", "invariant": "once",
                                      "context": self.a, "family": "RC-03", "resource": "slot",
                                      "order_matters": False,
                                      "members": [{"operation": op, "context": self.a, "intent": intent}
                                                  for op, intent in intents]})["scenario_id"]
        trial_id = None
        for size, mode, schedule in ((2, "vulnerable", "concurrent"),
                                     (2, "fixed", "fixed"),
                                     (4, "vulnerable", "concurrent"),
                                     (4, "fixed", "fixed")):
            tag = f"b13_{size}_{mode}"
            results = self.lab.group(tag, [op for op, _ in intents[:size]], mode=mode)
            self.assertEqual(self.lab.count, size if mode == "vulnerable" else 1)
            outcome = "observed" if mode == "vulnerable" else "negative-for-variant"
            receipt = self.race.record(self.lab_event(tag, results, schedule, outcome,
                                                       intents=intents[:size]))
            if size == 2 and mode == "vulnerable":
                trial_id = receipt["event_id"]
            self.assertEqual(receipt["success_ratio"], f"{size - 1 if mode == 'vulnerable' else 0}/{size}")
            self.assertTrue(receipt["sync_evidenced"])
        points = self.race.status()["scenarios"][-1]["points"]
        self.assertEqual([(p["parallelism"], p["ratio"]) for p in points], [(2, "1/2"), (4, "3/4")])
        self.assertIsNone(self.race.status()["scenarios"][-1]["window_return_to_contract_at"])
        self.assertEqual(self.ctx.store.network_attempts(), 0)  # direct owned loopback, not recon send
        self.assertTrue(self.race.verify()["verified"])
        copied = self.ctx.store.db.execute("SELECT path FROM workflow_artifacts WHERE event_id=? AND role='oracle'",
                                           (trial_id,)).fetchone()[0]
        (self.root / copied).write_text("tampered source")
        self.assertFalse(self.race.verify()["verified"])
        self.assertEqual([(p["parallelism"], p["ratio"]) for p in
                          self.race.status()["scenarios"][-1]["points"]], [(4, "3/4")])

    def test_b18_replayed_loopback_overrun_to_owned_synthetic_credit_t4(self):
        for name, reverse in (("b18ab", False), ("b18ba", True)):
            results = self.lab.exercise(name, reverse=reverse)
            self.race.record(self.lab_event(name, results,
                                            "serial-ba" if reverse else "serial-ab",
                                            "negative-for-variant"))
        vulnerable = self.lab.exercise("b18trial", concurrent=True)
        trial = self.race.record(self.lab_event("b18trial", vulnerable, "concurrent", "observed"))
        fixed = self.lab.exercise("b18fixed", mode="fixed", concurrent=True)
        self.race.record(self.lab_event("b18fixed", fixed, "fixed", "negative-for-variant"))
        receiver = OwnedCommerce()
        delta = receiver.credit_one_owned_resource({"effects": ["claim", "redeem"]},
                                                   {"effects": ["claim"]}, cap_minor=10)
        self.assertEqual((delta, receiver.receiver), (10, [{"owned-credit-minor": 10}]))
        finding = Findings(self.ctx)
        fid, _ = finding.add("owned lab credit effect", "business-logic",
                             url=f"http://127.0.0.1:{self.lab.port}/claim",
                             detail={"lineage": trial["lineage"]})
        replay_proof = self.root / artifact(self.root, "b18-target-replay.txt",
                                            json.dumps(receiver.receiver) + " owned credit")
        control = self.root / artifact(self.root, "b18-target-control.txt",
                                       "fixed no extra credit")
        impact = self.root / artifact(self.root, "b18-target-impact.txt",
                                      "owned synthetic value-delta minor 10")
        finding.move(fid, "confirmed", replay=replay_proof, control=control)
        finding.move(fid, "impact-proven", impact=impact)
        replay = self.lab.exercise("b18replay", concurrent=True)
        env = self.lab_event("b18replay", replay, "replay", "observed", replay_of=trial["event_id"])
        env.update({"impact_tier": "T4", "chain_finding": fid,
                    "attacker_gain": "one synthetic owned credit of ten minor units"})
        env["artifacts"] += ["lab-rehearsal=" + artifact(self.root, "b18-rehearsal.txt",
                             json.dumps({"delta_minor": delta, "receiver": receiver.receiver}) +
                             " owned loopback redemption")]
        last = self.race.record(env)
        self.assertEqual(last["impact_tier"], "T4")
        self.assertIn("race-eligible for human validation", last["causality"])
        self.assertFalse(last["finding_promoted"])
        self.assertEqual(self.race.status()["scenarios"][0]["points"][0]["ratio"], "1/2")
        self.assertTrue(self.race.verify()["verified"])
        for recorded in (trial, last):
            marker = self.ctx.store.db.execute("SELECT marker FROM workflow_events WHERE id=?",
                                               (recorded["event_id"],)).fetchone()[0]
            self.race.model.cleanup(recorded["event_id"], "deleted", artifact(
                self.root, f"b18-cleanup-{recorded['event_id']}.txt", marker + " deleted"))
        self.assertEqual(self.race.model.obligations(), [])
