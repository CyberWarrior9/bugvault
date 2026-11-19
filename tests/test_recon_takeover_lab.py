"""Gate B: an owned in-process provider rehearsal, never a real takeover.

The provider, DNS capture and parent response are simulations. No socket, DNS,
provider account, browser or TLS session is used; HTTPS strings are references
only. The owned-lab channel records evidence without granting live execution.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.findings import Findings
from recon.fingerprint import takeover_match
from recon.pipeline import Recon
from recon.takeover import TakeoverLedger
from tests.test_recon import write_campaign


HOST = "old.acme.test"
TARGET = "old.herokuapp.com"
CONTROL_HOST = "control.acme.test"
MARKER = "bvto_owned_attempt_0123456789"
CONTROL_MARKER = "bvto_owned_control_9876543210"
CLEANUP_DUE = "2099-01-01T00:00:00+00:00"


class OwnedProviderLab:
    """Tiny namespace allocator, not an implementation of any cloud provider."""

    def __init__(self):
        self.resources = {}
        self.routes = {HOST: "old", CONTROL_HOST: "control"}
        self.history = []

    def _account(self, account):
        if account not in ("owned-A", "owned-B"):
            raise ValueError("only the two owned lab accounts exist")

    def claim(self, account, namespace):
        self._account(account)
        if namespace not in self.routes.values():
            raise ValueError("namespace is outside the owned lab")
        if namespace in self.resources:
            raise ValueError("namespace occupied")
        resource = f"owned-lab:{account}:{namespace}"
        self.resources[namespace] = {"account": account, "resource": resource,
                                     "body": b"Owned lab deployment; marker not served yet\n"}
        receipt = {"operation": "claim", "account": account, "namespace": namespace,
                   "resource": resource, "simulation_only": True}
        self.history.append(receipt)
        return dict(receipt)

    def serve(self, account, namespace, body):
        self._account(account)
        obj = self.resources[namespace]
        if obj["account"] != account:
            raise ValueError("resource belongs to the other owned account")
        if not isinstance(body, bytes) or len(body) > 512 or b"<" in body or b"\x00" in body:
            raise ValueError("only tiny inert text is supported")
        obj["body"] = body

    def deploy(self, account, namespace, body):
        receipt = self.claim(account, namespace)
        self.serve(account, namespace, body)
        return receipt

    def availability(self, namespace):
        return {"namespace": namespace, "available": namespace not in self.resources,
                "simulation_only": True, "provider_specific_claimability": "not tested"}

    def read(self, hostname):
        # This is a dictionary lookup, not a resolver or HTTP client.
        obj = self.resources.get(self.routes[hostname])
        return {"host": hostname, "status": 200 if obj else 404,
                "content_type": "text/plain", "simulation_only": True,
                "body": obj["body"].decode() if obj else "No such app\n"}

    def release(self, account, namespace):
        self._account(account)
        obj = self.resources[namespace]
        if obj["account"] != account:
            raise ValueError("resource belongs to the other owned account")
        del self.resources[namespace]
        receipt = {"operation": "release", "account": account, "namespace": namespace,
                   "resource": obj["resource"], "released": True, "simulation_only": True}
        self.history.append(receipt)
        return dict(receipt)


class OwnedTakeoverLabTests(unittest.TestCase):
    def setUp(self):
        self.network_guards = []
        for target in ("socket.socket", "socket.getaddrinfo", "subprocess.Popen",
                       "recon.net.ScopedClient.request", "recon.net.PassiveClient.get",
                       "recon.net.PassiveClient.post_json"):
            guard = patch(target, side_effect=AssertionError("owned in-process lab: no network or subprocess"))
            self.network_guards.append(guard.start())
            self.addCleanup(guard.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        campaign = write_campaign(self.root, "active", [], in_scope=["acme.test", "*.acme.test"])
        self.ctx = Recon(campaign, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.findings = Findings(self.ctx)
        self.ledger = TakeoverLedger(self.ctx)
        self.lab = OwnedProviderLab()
        self.original = self.lab.deploy("owned-A", "old", b"Owned A original deployment\n")
        self.lab.deploy("owned-A", "control", ("Owned negative control " + CONTROL_MARKER + "\n").encode())
        self.addCleanup(self.lab.resources.clear)

        # Synthetic captured parent metadata, not browser/cookie/TLS behavior.
        self.parent_response = self.ctx.store.record_request(
            "GET", "https://acme.test/", 200, "owned-lab-parent-capture", [],
            {"set-cookie": "lab_preference=inert; Domain=acme.test; Path=/; Secure; HttpOnly",
             "content-security-policy": "default-src 'self'; script-src https://old.acme.test",
             "access-control-allow-origin": "https://old.acme.test",
             "access-control-allow-credentials": "true"},
            b"Owned parent response; references are conditional only\n",
            body_complete=True, basis="owned-lab")
        observed = datetime.now(timezone.utc).isoformat()
        self.capture = {
            "schema": 1, "source": "owned-in-process-provider-simulation",
            "observations": [
                {"name": name, "record_type": kind, "value": value, "result": result,
                 "resolver": "127.0.0.1", "observed_at": observed, "vantage": "recursive"}
                for name, kind, value, result in (
                    (HOST, "CNAME", TARGET, "answer"),
                    (TARGET, "A", "", "nxdomain"),
                    (TARGET, "AAAA", "", "nxdomain"))]}
        imported = self.ledger.import_capture(self.capture)
        self.assertFalse(imported["executed"])
        # Import creates the candidate asset. Settle its inventory before stages;
        # never sync again between precheck, claimability and claim evidence.
        self.ledger.sync()
        candidates = self.ledger.plan()["candidates"]
        matches = [c for c in candidates if c["name"] == HOST and c["value"] == TARGET]
        self.assertEqual(len(matches), 1, candidates)
        self.cid = matches[0]["id"]
        self.snapshot = matches[0]["snapshot"]
        guard = patch.object(self.ledger, "sync", side_effect=AssertionError("stage snapshot must stay stable"))
        self.sync_guard = guard.start()
        self.addCleanup(guard.stop)

    def tearDown(self):
        self.assertEqual(self.ctx.store.jobs(), [])
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        self.assertEqual(self.findings.all(), [])
        # The single request row is an explicitly labelled synthetic capture.
        rows = self.ctx.store.db.execute("SELECT id FROM requests").fetchall()
        self.assertEqual([row["id"] for row in rows], [self.parent_response])
        self.assertEqual(self.ctx.store.response(self.parent_response)["basis"], "owned-lab")
        self.assertEqual(self.ledger.show(self.cid)["snapshot"], self.snapshot)
        self.sync_guard.assert_not_called()
        for guard in self.network_guards:
            guard.assert_not_called()

    def save(self, name, value):
        path = self.root / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value, sort_keys=True))
        return str(path.relative_to(self.root))

    def event(self, stage, artifacts, **extra):
        return {"schema": 1, "candidate": self.cid, "stage": stage, "state": "observed",
                "channel": "owned-lab", "requests": 0, "artifacts": artifacts,
                "note": "Owned in-process simulation only; no provider, browser or TLS certification",
                **extra}

    def precheck(self):
        return self.ledger.record(self.event("precheck", {
            "review": self.save("review.txt", "Owned A/B namespace rehearsal only; no live claim permission. "
                                "CNAME and missing addresses are leads; parent trust is conditional.")}))

    def claimability_artifacts(self):
        return {
            "provider": self.save("provider.json", {"simulation_only": True, "provider": "heroku",
                "live_status": "unknown", "requirements": "this lab accepts only owned-A and owned-B",
                "reviewed_at": datetime.now(timezone.utc).isoformat()}),
            "namespace": self.save("namespace.json", self.lab.availability("old")),
            "control": self.save("namespace-control.json", self.lab.availability("control"))}

    def prepare_claim(self):
        self.precheck()
        self.lab.release("owned-A", "old")
        before = self.lab.read(HOST)
        self.assertEqual(before["status"], 404)
        self.assertNotIn(MARKER, before["body"])
        self.assertTrue(self.lab.availability("old")["available"])
        self.assertFalse(self.lab.availability("control")["available"])
        self.ledger.record(self.event("claimable", self.claimability_artifacts()))
        ownership = self.lab.claim("owned-B", "old")
        self.lab.serve("owned-B", "old", ("Inert owned B marker " + MARKER + "\n").encode())
        after, control = self.lab.read(HOST), self.lab.read(CONTROL_HOST)
        self.assertEqual(after["status"], 200)
        self.assertIn(MARKER, after["body"])
        self.assertNotIn(MARKER, control["body"])
        return self.event("claim", {
            "permission": self.save("permission.txt", "Permission for this in-process owned simulation only"),
            "ownership": self.save("ownership.json", ownership),
            "before": self.save("before.json", before),
            "after": self.save("after.json", after),
            "control": self.save("control.json", control),
            "cleanup_plan": self.save("cleanup-plan.json", {"owner": "owned-B", "due": CLEANUP_DUE,
                "action": "release old namespace and verify empty; release owned A control"})},
            marker=MARKER, control_marker=CONTROL_MARKER, account="owned-B",
            resource=ownership["resource"], cleanup_owner="owned-B", cleanup_due=CLEANUP_DUE)

    def release_claim(self, event):
        released = self.lab.release("owned-B", "old")
        self.assertEqual(self.lab.read(HOST)["status"], 404)
        self.assertTrue(self.lab.availability("old")["available"])
        receipt = self.save("cleanup-receipt.json", {
            "resource": released["resource"],
            "release": released, "readback": self.lab.read(HOST),
            "namespace": self.lab.availability("old")})
        result = self.ledger.cleanup({"schema": 1, "event": event["event_id"],
            "outcome": "released", "artifact": receipt, "note": "Owned B resource released in simulation"})
        self.assertFalse(result["executed"])
        self.assertEqual(result["outcome"], "released")
        self.lab.release("owned-A", "control")
        self.assertEqual(self.lab.resources, {})
        return result

    def test_owned_lifecycle_records_claim_then_cleanup_without_finding(self):
        claim = self.prepare_claim()
        result = self.ledger.record(claim)
        self.assertFalse(result["executed"])
        self.assertFalse(result["finding_promoted"])
        status = self.ledger.status()
        self.assertEqual(status["cleanup_open"], [{"event": result["event_id"], "candidate": self.cid,
            "owner": "owned-B", "due": CLEANUP_DUE, "overdue": False}])
        self.assertTrue(status["integrity"]["ok"], status["integrity"])
        events = self.ledger.show(self.cid)["events"]
        self.assertEqual([e["stage"] for e in events], ["precheck", "claimable", "claim"])
        self.assertTrue(all(not e["stale"] for e in events))
        self.assertTrue(all(e["data"]["channel"] == "owned-lab" and e["data"]["requests"] == 0 for e in events))
        self.assertEqual(events[-1]["data"]["resource"], "owned-lab:owned-B:old")
        self.release_claim(result)
        status = self.ledger.status()
        self.assertEqual(status["cleanup_open"], [])
        self.assertTrue(status["integrity"]["ok"], status["integrity"])
        self.assertFalse(status["coverage_complete"])
        self.assertEqual([(h["operation"], h["account"], h["namespace"]) for h in self.lab.history], [
            ("claim", "owned-A", "old"), ("claim", "owned-A", "control"),
            ("release", "owned-A", "old"), ("claim", "owned-B", "old"),
            ("release", "owned-B", "old"), ("release", "owned-A", "control")])

    def test_occupied_namespace_rejects_other_account_at_provider(self):
        self.precheck()
        original = self.lab.read(HOST)
        with self.assertRaisesRegex(ValueError, "occupied"):
            self.lab.claim("owned-B", "old")
        with self.assertRaisesRegex(ValueError, "other owned account"):
            self.lab.serve("owned-B", "old", MARKER.encode())
        with self.assertRaisesRegex(ValueError, "other owned account"):
            self.lab.release("owned-B", "old")
        self.assertEqual(self.lab.read(HOST), original)
        self.assertEqual(self.lab.resources["old"]["resource"], self.original["resource"])
        result = self.ledger.record(self.event("claimable", {
            "namespace": self.save("occupied.json", self.lab.availability("old"))},
            state="negative", note="Owned lab rejected B: namespace remains occupied by A"))
        self.assertFalse(result["finding_promoted"])
        self.assertEqual(self.ledger.show(self.cid)["events"][-1]["state"], "negative")
        self.assertEqual(self.ledger.status()["cleanup_open"], [])

    def test_empty_namespace_signature_is_not_claimability_evidence(self):
        self.precheck()
        self.lab.release("owned-A", "old")
        empty = self.lab.read(HOST)
        self.assertIn("heroku", takeover_match(empty["body"]))
        self.assertEqual(empty["status"], 404)
        # A suffix, missing addresses and a recognized empty-page signature do
        # not supply the provider review, namespace check and occupied control.
        with self.assertRaisesRegex(ValueError, "requires roles"):
            self.ledger.record(self.event("claimable", {"namespace": self.save("empty.json", empty)}))
        artifacts = {role: self.save(role + ".txt", role + " simulation") for role in
                     ("permission", "ownership", "before", "after", "control", "cleanup_plan")}
        with self.assertRaisesRegex(ValueError, "claimability"):
            self.ledger.record(self.event("claim", artifacts))
        self.assertEqual([e["stage"] for e in self.ledger.show(self.cid)["events"]], ["precheck"])
        self.assertEqual(self.ledger.status()["cleanup_open"], [])

    def test_claimability_requires_precheck_and_distinct_namespace_control(self):
        self.lab.release("owned-A", "old")
        artifacts = self.claimability_artifacts()
        with self.assertRaisesRegex(ValueError, "precheck"):
            self.ledger.record(self.event("claimable", artifacts))
        self.assertEqual(self.ledger.show(self.cid)["events"], [])
        self.precheck()
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.ledger.record(self.event("claimable", {**artifacts, "control": artifacts["namespace"]}))
        self.assertEqual(len(self.ledger.show(self.cid)["events"]), 1)

    def test_claim_marker_and_negative_control_mismatches_fail_before_event_write(self):
        claim = self.prepare_claim()
        variants = [
            {"after": self.save("no-marker.txt", "Owned B response without the attempt marker")},
            {"control": self.save("contaminated-control.txt", MARKER + " " + CONTROL_MARKER)},
            {"control": self.save("wrong-control.txt", "bvto_unrelated_control_000000")},
            {"before": self.save("preexisting-marker.txt", "Already served " + MARKER)},
        ]
        for changed in variants:
            with self.subTest(artifact=next(iter(changed))):
                with self.assertRaisesRegex(ValueError, "marker|control|receipt"):
                    self.ledger.record({**claim, "artifacts": {**claim["artifacts"], **changed}})
                self.assertEqual(len(self.ledger.show(self.cid)["events"]), 2)
                self.assertEqual(self.ledger.status()["cleanup_open"], [])
        for changed in ({"control_marker": MARKER}, {"marker": "too_short"}):
            with self.subTest(markers=changed), self.assertRaisesRegex(ValueError, "markers"):
                self.ledger.record({**claim, **changed})
        # Invalid evidence did not poison the valid attempt or its cleanup.
        self.release_claim(self.ledger.record(claim))

    def test_parent_trust_and_claim_do_not_prove_chain_or_tls(self):
        result = self.ledger.record(self.prepare_claim())
        shown = self.ledger.show(self.cid)
        edges = shown["trust_edges"]
        self.assertTrue({"cookie-domain", "csp-script", "cors"} <= {e["kind"] for e in edges}, edges)
        for edge in edges:
            self.assertEqual(edge["source_kind"], "response")
            self.assertEqual(edge["source_ref"], str(self.parent_response))
            self.assertEqual(len(edge["source_sha256"]), 64)
        self.assertIn("conditional", shown["impact"])
        self.assertGreater(shown["priority"], 0)
        # Captured parent trust is not a browser replay or downstream effect.
        with self.assertRaisesRegex(ValueError, "requires roles"):
            self.ledger.record(self.event("chain", {
                "trust": self.save("conditional-trust.json", edges)},
                marker=MARKER, control_marker=CONTROL_MARKER))
        self.ledger.record(self.event("chain", {}, state="inconclusive",
            note="Cookie delivery, CSP execution, CORS readability and independent impact not exercised"))
        shown = self.ledger.show(self.cid)
        self.assertIn("conditional", shown["impact"])
        self.assertEqual(shown["events"][-1]["state"], "inconclusive")
        self.assertFalse(any(e["stage"] == "tls" for e in shown["events"]))
        self.release_claim(result)

    def test_chain_rejects_mismatched_negative_control(self):
        claim = self.prepare_claim()
        result = self.ledger.record(claim)
        count = len(self.ledger.show(self.cid)["events"])
        artifacts = {"replay": claim["artifacts"]["after"],
            "control": self.save("wrong-chain-control.txt", "Different unrelated owned response"),
            "impact": self.save("synthetic-impact.txt", "Synthetic artifact; not a real downstream proof")}
        with self.assertRaisesRegex(ValueError, "round trip"):
            self.ledger.record(self.event("chain", artifacts, marker=MARKER, control_marker=CONTROL_MARKER))
        self.assertEqual(len(self.ledger.show(self.cid)["events"]), count)
        self.assertIn("conditional", self.ledger.show(self.cid)["impact"])
        self.release_claim(result)

    def test_owned_lab_evidence_does_not_grant_live_channel(self):
        claim = self.prepare_claim()
        raw = self.ctx.campaign.raw
        self.assertFalse(raw.get("program_url"))
        self.assertEqual(raw.get("takeover", {}).get("grants", []), [])
        self.assertEqual(raw.get("takeover", {}).get("budget", 0), 0)
        for channel in ("browser", "burp", "native", "scanner"):
            with self.subTest(channel=channel), self.assertRaisesRegex(ValueError, "live takeover evidence"):
                self.ledger.record({**claim, "channel": channel, "requests": 1})
        self.assertEqual(len(self.ledger.show(self.cid)["events"]), 2)
        self.release_claim(self.ledger.record(claim))

    def test_provider_url_marker_cannot_substitute_for_candidate_receipt(self):
        claim = self.prepare_claim()
        wrong = self.save("provider-only.json", {"url": "https://old.herokuapp.com/", "body": MARKER})
        with self.assertRaisesRegex(ValueError, "candidate hostname"):
            self.ledger.record({**claim, "artifacts": {**claim["artifacts"], "after": wrong}})
        self.release_claim(self.ledger.record(claim))

    def test_cleanup_requires_exact_resource_and_blocks_another_claim(self):
        claim = self.prepare_claim()
        result = self.ledger.record(claim)
        with self.assertRaisesRegex(ValueError, "cleanup"):
            self.ledger.record(claim)
        with self.assertRaisesRegex(ValueError, "claimed resource"):
            self.ledger.cleanup({"schema": 1, "event": result["event_id"], "outcome": "deleted",
                "artifact": self.save("wrong-release.txt", "a different resource was deleted"), "note": "wrong object"})
        self.assertEqual(len(self.ledger.status()["cleanup_open"]), 1)
        self.release_claim(result)

    def test_claim_marker_in_request_metadata_is_not_response_proof(self):
        claim = self.prepare_claim()
        wrong = self.save("metadata-marker.json", {"request_url": f"https://{HOST}/?marker={MARKER}",
            "status": 200, "body": "No marker served in this response"})
        with self.assertRaisesRegex(ValueError, "round trip"):
            self.ledger.record({**claim, "artifacts": {**claim["artifacts"], "after": wrong}})
        self.release_claim(self.ledger.record(claim))

    def test_validation_and_copy_share_the_same_immutable_bytes(self):
        claim = self.prepare_claim()
        original_keep = self.ledger._keep
        after_path = self.root / claim["artifacts"]["after"]
        changed = [False]
        def replace_source_after_validation(raw):
            if not changed[0]:
                after_path.write_text(json.dumps({"host": HOST, "status": 200, "body": "replaced source"}))
                changed[0] = True
            return original_keep(raw)
        with patch.object(self.ledger, "_keep", side_effect=replace_source_after_validation):
            result = self.ledger.record(claim)
        event = self.ledger.show(self.cid)["events"][-1]
        stored = json.loads((self.root / event["data"]["artifacts"]["after"]["path"]).read_text())
        self.assertIn(MARKER, stored["body"])
        self.assertTrue(self.ledger.verify()["ok"])
        self.release_claim(result)

    def test_resource_prefix_collision_does_not_close_cleanup(self):
        claim = self.prepare_claim()
        result = self.ledger.record(claim)
        with self.assertRaisesRegex(ValueError, "claimed resource"):
            self.ledger.cleanup({"schema": 1, "event": result["event_id"], "outcome": "deleted",
                "artifact": self.save("prefix-release.json", {"resource": claim["resource"] + "0", "deleted": True}),
                "note": "different resource"})
        self.assertEqual(len(self.ledger.status()["cleanup_open"]), 1)
        self.release_claim(result)

    def test_failed_cleanup_stops_live_success_but_keeps_blocked_evidence(self):
        claim = self.prepare_claim()
        result = self.ledger.record(claim)
        self.ledger.cleanup({"schema": 1, "event": result["event_id"], "outcome": "failed",
            "artifact": self.save("failed-release.json", {"resource": claim["resource"], "released": False}),
            "note": "owned simulation release failed"})
        for stage in ("precheck", "chain"):
            with self.subTest(stage=stage), self.assertRaisesRegex(ValueError, "cleanup blocks"):
                self.ledger.record(self.event(stage, {}, channel="burp", requests=1))
        self.ledger.record(self.event("chain", {}, channel="burp", state="blocked",
                                     note="Stopped for unresolved cleanup"))
        self.release_claim(result)


if __name__ == "__main__":
    unittest.main()
