"""RCE inventory and proof triage are offline, evidence-limited, and never findings."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon.cli import main
from recon.pipeline import Recon
from recon.rce import RceLedger
from recon.report import write_reports
from recon.skillmap import skills_for
from tests.test_recon import write_campaign


class RceReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        camp = write_campaign(Path(self.tmp.name) / "camp", "passive", [], in_scope=["acme.test"])
        self.root = camp.root
        self.ctx = Recon(camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.url = "https://acme.test/owned-report"
        self.asset, _ = self.ctx.store.upsert_asset("endpoint", self.url, attrs={"sources": ["har"]})
        self.ledger = RceLedger(self.ctx)
        self.put("entry.txt", b"owned capture name only")
        self.put("source.txt", b"approved excerpt identifying a worker, not source execution")

    def put(self, name, data):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        (self.root / name).write_bytes(data)
        return name

    def spec(self, **extra):
        value = {"schema": 1, "family": "command-injection", "url": self.url, "method": "POST",
                 "asset_id": self.asset, "field": "format", "location": "body",
                 "context": {"account": "owned-a", "role": "member", "tenant": "owned",
                             "workflow": "report"}, "consumer": "report-worker",
                 "sink_kind": "subprocess-argv", "runtime": "python", "tier": "review-only",
                 "edges": [
                     {"stage": "entry", "basis": "capture", "certainty": "direct",
                      "reference": "capture-1", "artifact": "entry.txt"},
                     {"stage": "sink", "basis": "authorized-source", "certainty": "direct",
                      "reference": "source-12", "artifact": "source.txt"}]}
        value.update(extra)
        return value

    def declare(self, **extra):
        self.put("sink.json", self.spec(**extra))
        return self.ledger.declare("sink.json")

    def receipt(self, sink, state="observed", channel="owned-lab", effect_channel="processing",
                **extra):
        value = {"schema": 1, "sink": sink, "state": state, "channel": channel,
                 "effect_channel": effect_channel, "artifacts": {"baseline": "entry.txt"}}
        value.update(extra)
        self.put("receipt.json", value)
        return self.ledger.record("receipt.json")

    def proof(self, sink, effect_channel="direct-output"):
        primary, replay, control = "bv_effect_1234567890", "bv_replay_1234567890", "bv_control_1234567890"
        content = {"baseline": "normal route", "trigger": "nonce abc", "replay-request": "nonce def",
                   "effect": "worker returned " + primary, "verification": "worker returned " + replay,
                   "negative-control": "fixed route " + control,
                   "positive-control": "healthy route " + control,
                   "cleanup": "no object remained", "worker-log": "worker " + primary,
                   "worker-replay": "worker " + replay}
        artifacts = {role: self.put(role + ".txt", value.encode()) for role, value in content.items()}
        times = {key: "2026-11-20T00:00:0%dZ" % i for i, key in enumerate(
            ("baseline", "trigger", "replay", "negative", "cleanup"), 1)}
        value = {"schema": 1, "sink": sink, "state": "execution-claimed", "channel": "owned-lab",
                 "effect_channel": effect_channel, "artifacts": artifacts,
                 "markers": {"effect": primary, "replay": replay, "control": control},
                 "fidelity": {role: {"complete": True, "encoding": "identity"} for role in
                              ("baseline", "effect", "verification", "negative-control",
                               "positive-control")},
                 "binding": {**self.spec()["context"], "consumer": "report-worker",
                             "owned_object": "lab-report-1"},
                 "times": times, "note": "owned-lab-only"}
        self.put("proof.json", value)
        return value

    def test_source_supported_only_on_exact_existing_endpoint(self):
        with patch("socket.socket", side_effect=AssertionError("offline")):
            result = self.declare()
        self.assertTrue(result["source_supported"])
        self.assertEqual(skills_for("command-injection"), ("hunt-rce",))
        self.assertEqual([(c["asset_id"], c["bug_class"], c["status"]) for c in
                          self.ctx.store.coverage()], [(self.asset, "command-injection", "untested")])
        self.assertFalse(result["executed"])
        self.assertEqual(self.ctx.store.jobs(), [])
        self.assertEqual(self.ctx.store.network_attempts(), 0)

    def test_unqualified_marker_or_client_only_stays_unseeded_lead(self):
        original = self.spec()
        original["edges"][-1]["basis"] = "capture"
        original["edges"][-1]["certainty"] = "inferred"
        original.pop("asset_id")
        original["consumer"] = "unknown"
        self.put("lead.json", original)
        lead = self.ledger.declare("lead.json")
        self.assertFalse(lead["source_supported"])
        self.assertEqual(self.ctx.store.coverage(), [])
        self.assertFalse(self.ledger.show(lead["id"])["qualified"])

    def test_empty_sink_artifact_is_not_source_support(self):
        self.put("source.txt", b"")
        self.assertFalse(self.declare()["source_supported"])
        self.assertEqual(self.ctx.store.coverage(), [])

    def test_deserialization_family_and_source_context_dedupe(self):
        self.put("sink.json", self.spec(family="deserialization", sink_kind="dotnet"))
        first = self.ledger.declare("sink.json")
        second = self.ledger.declare("sink.json")
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(first["coverage_seeded"])
        self.assertFalse(second["coverage_seeded"])
        self.assertEqual(skills_for("deserialization"), ("hunt-rce",))
        other = self.spec(family="deserialization", sink_kind="dotnet")
        other["context"]["account"] = "owned-b"
        self.put("other.json", other)
        self.assertNotEqual(self.ledger.declare("other.json")["id"], first["id"])
        self.assertEqual(len(self.ctx.store.coverage()), 1)  # coarse row, independent exact sinks

    def test_inferred_only_endpoint_remains_unqualified(self):
        # A captured source already exists, so use a distinct JS-only endpoint.
        candidate, _ = self.ctx.store.upsert_asset("endpoint", "https://acme.test/static-eval",
                                                   attrs={"sources": ["js"]})
        spec = self.spec(asset_id=candidate, url="https://acme.test/static-eval")
        self.put("client.json", spec)
        result = self.ledger.declare("client.json")
        self.assertFalse(result["source_supported"])
        self.assertEqual(self.ctx.store.coverage(), [])

    def test_method_path_and_intermediate_hop_do_not_silently_merge(self):
        self.ctx.store.update_attrs(self.asset, {"methods": ["POST"]})
        self.assertFalse(self.declare(method="GET")["source_supported"])
        spec = self.spec()
        spec["edges"].insert(1, {"stage": "queue", "basis": "owner-log",
                                 "certainty": "inferred", "reference": "worker-link",
                                 "artifact": "source.txt"})
        self.put("inferred.json", spec)
        self.assertFalse(self.ledger.declare("inferred.json")["source_supported"])
        self.assertEqual(self.ctx.store.coverage(), [])
        grouped = self.ctx.add_endpoint("https://acme.test/report/123", "har", method="POST")
        self.put("other-path.json", self.spec(asset_id=grouped, url="https://acme.test/report/456"))
        self.assertFalse(self.ledger.declare("other-path.json")["source_supported"])

    def test_captured_post_does_not_qualify_js_only_get_on_same_route(self):
        self.ctx.add_endpoint(self.url, "js", method="GET")
        self.ctx.add_endpoint(self.url, "har", method="POST")
        self.assertFalse(self.declare(method="GET")["source_supported"])
        self.put("captured-post.json", self.spec(method="POST"))
        self.assertTrue(self.ledger.declare("captured-post.json")["source_supported"])

    def test_label_only_never_leaks_raw_account_or_field(self):
        spec = self.spec(field="private-label", context={"account": "private-label", "role": "member",
                                                        "tenant": "private-label", "workflow": "report"})
        self.put("private.json", spec)
        shown = self.ledger.show(self.ledger.declare("private.json")["id"])
        self.assertNotIn("private-label", json.dumps(shown))
        self.assertEqual(len(shown["label_hashes"]["account"]), 16)

    def test_scope_method_asset_and_schema_fail_closed(self):
        variants = (self.spec(url="https://outside.test/owned-report"),
                    self.spec(asset_id=True), self.spec(method="EXEC"),
                    self.spec(url="https://acme.test/other"), self.spec(schema=True),
                    self.spec(family=[]), self.spec(method=[]), self.spec(location=[]),
                    self.spec(sink_kind=[]), self.spec(tier=[]),
                    self.spec(edges=[{"stage": [], "basis": "capture", "certainty": "direct",
                                      "reference": "capture", "artifact": "entry.txt"},
                                     self.spec()["edges"][-1]]))
        for value in variants:
            with self.subTest(value=value), self.assertRaises((ValueError, KeyError)):
                self.put("invalid.json", value)
                self.ledger.declare("invalid.json")
        self.assertEqual(self.ledger.status()["total"], 0)

    def test_private_query_and_source_tamper_are_not_exported(self):
        url = self.url + "?nonce=PRIVATE_QUERY"
        self.put("source.txt", b"source PRIVATE_BODY")
        result = self.declare(url=url)
        with patch("socket.socket", side_effect=AssertionError("offline")):
            shown = self.ledger.show(result["id"])
            write_reports(self.ctx)
        self.assertNotIn("PRIVATE_QUERY", json.dumps(shown))
        self.assertNotIn("PRIVATE_BODY", json.dumps(shown))
        self.assertTrue(self.ledger.verify()["ok"])
        self.put("source.txt", b"edited source")
        self.assertFalse(self.ledger.verify()["ok"])
        self.assertTrue(self.ledger.show(result["id"])["integrity_issues"])

    def test_callback_or_delay_stays_observation_even_with_artifacts(self):
        sink = self.declare()["id"]
        for effect in ("callback", "timing", "processing"):
            with self.subTest(effect=effect):
                result = self.receipt(sink, state="execution-claimed", effect_channel=effect)
                self.assertEqual(result["assessment"], "inconclusive")
                self.assertFalse(result["verification_eligible"])
        self.assertEqual(self.receipt(sink, effect_channel="callback")["assessment"],
                         "behavior-observed")
        self.proof(sink, effect_channel="callback")
        self.assertIn("callback, timing or processing", " ".join(
            self.ledger.record("proof.json")["reasons"]))

    def test_lab_receipt_is_eligible_only_for_human_review(self):
        sink = self.declare()["id"]
        value = self.proof(sink, effect_channel="owner-worker-log")
        with patch("socket.socket", side_effect=AssertionError("offline")):
            result = self.ledger.record("proof.json")
            self.assertTrue(self.ledger.verify()["ok"])
        self.assertEqual(result["assessment"], "eligible-for-validator")
        self.assertTrue(result["verification_eligible"])
        self.assertFalse(result["finding_promoted"])
        self.assertFalse(result["executed"])
        self.assertEqual(self.ledger.show(result["id"])["assessment"]["assessment"],
                         "eligible-for-validator")
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        self.assertEqual(self.ctx.store.jobs(), [])
        self.assertEqual(self.ledger.status(limit=1)["next_offset"], 1)
        self.assertFalse(self.ledger.verify(limit=1)["complete"])
        # A fabricated worker log may meet byte rules, but human review is indispensable.
        self.assertIn("semantic review", result["reasons"][0])

    def test_reflection_missing_worker_and_incomplete_capture_fail(self):
        sink = self.declare()["id"]
        value = self.proof(sink, effect_channel="owner-worker-log")
        value["artifacts"].pop("worker-replay")
        self.put("proof.json", value)
        self.assertEqual(self.ledger.record("proof.json")["assessment"], "inconclusive")
        value = self.proof(sink)
        self.put("trigger.txt", value["markers"]["effect"].encode())
        self.assertEqual(self.ledger.record("proof.json")["assessment"], "inconclusive")
        value = self.proof(sink)
        value["fidelity"]["effect"]["complete"] = False
        self.put("proof.json", value)
        self.assertEqual(self.ledger.record("proof.json")["assessment"], "inconclusive")
        value = self.proof(sink)
        value["fidelity"]["negative-control"]["complete"] = False
        self.put("proof.json", value)
        self.assertEqual(self.ledger.record("proof.json")["assessment"], "inconclusive")
        value = self.proof(sink)
        value.pop("binding")
        self.put("proof.json", value)
        self.assertEqual(self.ledger.record("proof.json")["assessment"], "inconclusive")
        value = self.proof(sink)
        value["binding"]["tenant"] = "other-tenant"
        self.put("proof.json", value)
        with self.assertRaisesRegex(ValueError, "actor/worker"):
            self.ledger.record("proof.json")
        value = self.proof(sink)
        self.put("replay-request.txt", b"nonce abc")
        self.assertEqual(self.ledger.record("proof.json")["assessment"], "inconclusive")

    def test_receipt_depends_on_sink_original_and_policy(self):
        sink = self.declare()["id"]
        rid = self.receipt(sink)["id"]
        self.put("sink.json", {**self.spec(), "runtime": "other"})
        self.assertFalse(self.ledger.verify()["ok"])
        self.assertTrue(self.ledger.show(rid)["integrity_issues"])
        with self.assertRaisesRegex(ValueError, "stale"):
            self.receipt(sink)

    def test_truncated_receipt_is_stale_and_not_a_current_lab_bundle(self):
        sink = self.declare()["id"]
        self.proof(sink)
        review = self.ledger.record("proof.json")
        self.assertEqual(review["assessment"], "eligible-for-validator")
        self.put("effect.txt", b"truncated after capture")
        self.assertFalse(self.ledger.verify()["ok"])
        self.assertTrue(self.ledger.show(review["id"])["integrity_issues"])

    def test_invalid_private_snapshot_fails_verification_without_crashing_report(self):
        sink = self.declare()["id"]
        self.ctx.store.db.execute("UPDATE offline_reviews SET data=? WHERE id=?",
                                  ("{not-json", sink))
        self.ctx.store.db.commit()
        self.assertTrue(self.ledger.show(sink)["integrity_issues"])
        self.assertFalse(self.ledger.verify()["ok"])
        self.assertTrue(self.ledger.status()["rows"][0]["integrity_issues"])
        self.assertTrue(write_reports(self.ctx))

    def test_policy_changes_and_untrusted_receipt_shapes_fail_closed(self):
        sink = self.declare()["id"]
        bad = [self.proof(sink, effect_channel="callback")]
        bad[0]["state"] = []
        bad += [{**self.proof(sink), "channel": []},
                {**self.proof(sink), "artifacts": []},
                {**self.proof(sink), "markers": []},
                {**self.proof(sink), "fidelity": {"effect": ["complete"]}},
                {**self.proof(sink), "times": {"baseline": []}},
                {**self.proof(sink), "binding": []}]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError):
                self.put("bad-receipt.json", item)
                self.ledger.record("bad-receipt.json")
        self.ctx.campaign.raw.setdefault("rules", {})["reviewed"] = "changed"
        self.assertFalse(self.ledger.verify()["ok"])
        self.assertTrue(self.ledger.show(sink)["integrity_issues"])

    def test_referenced_source_cannot_escape_campaign_or_be_a_symlink(self):
        self.put("bad.json", self.spec(edges=[{**self.spec()["edges"][0],
                                                "artifact": "../outside.txt"},
                                               self.spec()["edges"][1]]))
        with self.assertRaisesRegex(ValueError, "campaign"):
            self.ledger.declare("bad.json")
        (self.root / "link.txt").symlink_to(self.root / "source.txt")
        self.put("bad.json", self.spec(edges=[self.spec()["edges"][0],
                                               {**self.spec()["edges"][1], "artifact": "link.txt"}]))
        with self.assertRaisesRegex(ValueError, "symlinks"):
            self.ledger.declare("bad.json")

    def test_cli_and_report_view_without_raw_values(self):
        self.put("sink.json", self.spec(url=self.url + "?private=PRIVATE_QUERY"))
        with patch("socket.socket", side_effect=AssertionError("offline")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["rce", "declare", str(self.root), "--file", "sink.json"]), 0)
            self.assertEqual(main(["rce", "status", str(self.root)]), 0)
            self.assertEqual(main(["rce", "verify", str(self.root)]), 0)
        self.assertNotIn("PRIVATE_QUERY", out.getvalue())
        report = write_reports(self.ctx)
        coverage = next(p for p in report if p.name == "coverage.md").read_text()
        self.assertIn("RCE sink and owned-lab evidence reviews", coverage)
        self.assertNotIn("PRIVATE_QUERY", coverage)


if __name__ == "__main__":
    unittest.main()
