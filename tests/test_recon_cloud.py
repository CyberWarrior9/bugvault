"""Cloud M1–M3 offline integration; no target/provided cloud credentials."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon.campaign import Campaign, ConfigError
from recon.cli import main
from recon.cloud import CloudLedger
from recon.cloud_refs import cloud_references
from recon.pipeline import Recon
from recon.report import write_reports
from recon.skillmap import skills_for
from tests.test_recon import write_campaign


class CloudReferencesTests(unittest.TestCase):
    def test_scoped_identifiers_and_public_configs_are_leads_not_permissions(self):
        text = ("upload s3://team-fixture/marker and arn:aws:iam::123456789012:role/Test "
                "gs://team-fixture and "
                "https://acctname.blob.core.windows.net/private/a?sig=not-a-secret "
                "identityPoolId:'us-east-1:01234567-0123-0123-0123-012345678901' "
                "monitorId:'01234567-0123-0123-0123-012345678901' "
                "projectId:'fixture-project' "
                "https://storage.googleapis.com/test-public/x")
        found = cloud_references(text, source_ref="fixture:1", media_type="text/plain")
        kinds = {r["resource_kind"] for r in found}
        self.assertTrue({"s3-bucket", "arn", "gcs-bucket", "blob-container",
                         "cognito-pool", "rum-monitor", "firebase-project"} <= kinds)
        self.assertTrue(all(r["ownership"] == "unknown" for r in found))
        self.assertTrue(any(r["signed_context"] for r in found))
        self.assertNotIn("sig=", json.dumps(found))
        self.assertEqual(cloud_references(text, source_ref="fixture:1", media_type="text/plain"), found)
        self.assertTrue(any("public-identifier" in r["triage_signals"] for r in found))

    def test_secrets_and_signed_urls_do_not_leak(self):
        text = ("https://team-fixture.s3.amazonaws.com/path?X-Amz-Signature=abc "
                "AKIAABCDEFGHIJKLMNOP")
        found = cloud_references(text, source_ref="fixture:2", media_type="text/plain")
        self.assertEqual(found[0]["native_identifier"], "team-fixture")
        self.assertTrue(found[0]["signed_context"])
        self.assertNotIn("AKIA", json.dumps(found))
        self.assertNotIn("X-Amz-Signature", json.dumps(found))

    def test_provider_scope_collisions_and_archived_decay(self):
        text = "arn:aws:iam::123456789012:role/Foo arn:aws-cn:iam::123456789012:role/Foo"
        found = cloud_references(text, source_ref="fixture:3", media_type="text/plain")
        self.assertNotEqual(found[0]["scope"]["partition"], found[1]["scope"]["partition"])
        aged = cloud_references(text, source_ref="fixture:3", media_type="text/plain", historical=True)
        self.assertLess(aged[0]["probe_priority"], found[0]["probe_priority"])

    def test_bounded_inputs_and_unsafe_source_labels(self):
        with self.assertRaises(ValueError):
            cloud_references("s3://testbucket", source_ref="https://x/?token=secret", media_type="text/plain")
        with self.assertRaises(ValueError):
            cloud_references("a" * 2_000_001, source_ref="fixture:1", media_type="text/plain")
        with self.assertRaisesRegex(ValueError, "safe source"):
            cloud_references("s3://testbucket", source_ref="AKIAABCDEFGHIJKLMNOP", media_type="text/plain")

    def test_no_query_in_value_or_object_key_in_identifier(self):
        text = 'https://team-fixture.s3.amazonaws.com/private/key?X-Amz-Signature=value'
        found = cloud_references(text, source_ref="fixture:4", media_type="text/plain")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["native_identifier"], "team-fixture")
        self.assertNotIn("private", json.dumps(found))


class CloudLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.camp = write_campaign(self.root, "active", [], in_scope=["acme.test", "*.acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.ledger = CloudLedger(self.ctx)

    def file(self, path, content):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return path

    def ref(self):
        self.file("evidence/app.js", 'upload("s3://owned-fixture/canary")')
        result = self.ledger.import_text("evidence/app.js")
        self.assertFalse(result["executed"])
        return self.ledger.plan()["candidates"][0]["id"]

    def event(self, reference, **changes):
        base = {"schema": 1, "reference": reference, "case": "CM-02",
                "state": "inconclusive", "channel": "offline",
                "operation": {"principal": "anonymous", "action": "s3:PutObject",
                              "resource_id": "owned-fixture", "method": "PUT"},
                "reason": "Requires a scoped approved test"}
        return {**base, **changes}

    def test_import_deduplicates_no_jobs_and_cannot_contact_targets(self):
        self.file("evidence/text", "s3://owned-fixture/key")
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            first = self.ledger.import_text("evidence/text")
            again = self.ledger.import_text("evidence/text")
        self.assertEqual(first["source"], again["source"])
        self.assertEqual(self.ledger.status()["candidates"], 1)
        self.assertEqual(self.ctx.store.jobs(), [])
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        self.assertFalse(self.ledger.plan()["coverage_complete"])

    def test_sync_only_stored_in_scope_responses_and_source_integrity(self):
        rid = self.ctx.store.record_request("GET", "https://app.acme.test/a.js", 200, "fixture", [], {},
                                            b'fetch("https://team-fixture.s3.amazonaws.com/key?sig=x")',
                                            body_complete=True, basis="owned-fixture")
        self.ctx.store.record_request("GET", "https://other.test/a.js", 200, "fixture", [], {},
                                      b'"s3://someone-else/resource"', body_complete=True)
        with patch("socket.socket", side_effect=AssertionError("sync is offline")):
            result = self.ledger.sync()
        self.assertEqual(result["sources_added"], 1)
        self.assertEqual(len(result["gaps"]), 1)
        self.ctx.store.upsert_asset("js", "https://app.acme.test/a.js", host="app.acme.test")
        self.assertEqual(self.ledger.sync()["sources_added"], 0)
        self.assertEqual(skills_for("cloud-misconfiguration"), ("hunt-cloud-misconfig",))
        self.assertTrue(any(r["bug_class"] == "cloud-misconfiguration"
                            for r in self.ctx.store.coverage()))
        self.assertTrue(self.ledger.verify()["ok"])
        self.assertTrue(self.ledger.plan()["candidates"][0]["capture_complete"])
        response = self.ctx.store.response(rid)
        (self.ctx.store.bodies_dir / response["body_sha256"]).write_text("tampered")
        self.assertFalse(self.ledger.verify()["ok"])

    def test_incomplete_capture_and_invalid_utf8_preserve_gaps(self):
        rid = self.ctx.store.record_request("GET", "https://app.acme.test/partial.js", 200,
                                            "fixture", [], {}, b's3://bounded-bucket/part',
                                            body_complete=False, basis="fixture")
        self.ledger.sync()
        self.assertFalse(self.ledger.plan()["candidates"][0]["capture_complete"])
        self.assertEqual(self.ctx.store.response(rid)["body_complete"], 0)
        invalid = self.root / "bad.txt"
        invalid.write_bytes(b"s3://abc\xffdef")
        with self.assertRaises(UnicodeError):
            self.ledger.import_text("bad.txt")
        self.assertEqual(self.ledger.status()["sources"], 1)

    def test_sync_pages_older_captures_and_reports_remaining_work(self):
        for i in range(4):
            self.ctx.store.record_request("GET", f"https://app.acme.test/{i}.js", 200,
                                          "fixture", [], {}, f"s3://bucket-{i}/object".encode(),
                                          body_complete=True, basis="fixture")
        with patch("socket.socket", side_effect=AssertionError("sync is offline")):
            first = self.ledger.sync(limit=2)
            self.assertEqual(first["next_offset"], 2)
            second = self.ledger.sync(limit=2, offset=first["next_offset"])
        self.assertIsNone(second["next_offset"])
        self.assertEqual(self.ledger.status()["sources"], 4)
        self.assertEqual(self.ledger.status()["candidates"], 4)
        with self.assertRaisesRegex(ValueError, "offset"):
            self.ledger.sync(limit=2, offset=-1)
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(["cloud", "sync", str(self.root), "--limit", "2",
                                   "--offset", "2"]), 0)
        self.assertIn('"offset": 2', stdout.getvalue())

    def test_provenance_tamper_and_stale_policy(self):
        ref = self.ref()
        self.ledger.record(self.event(ref))
        self.assertTrue(self.ledger.verify()["ok"])
        self.file("evidence/app.js", "s3://new-bucket/key")
        self.assertFalse(self.ledger.verify()["ok"])
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.ledger.record(self.event(ref))
        self.file("evidence/app.js", 'upload("s3://owned-fixture/canary")')
        self.camp.raw["rules"] = ["new policy snapshot"]
        self.assertTrue(self.ledger.show(ref)["events"][0]["stale"])
        self.assertFalse(self.ledger.verify()["ok"])

    def test_reference_selector_tamper_blocks_new_events(self):
        ref = self.ref()
        self.ctx.store.db.execute("UPDATE cloud_refs SET native_identifier=? WHERE id=?",
                                  ("other-bucket", ref))
        self.ctx.store.db.commit()
        self.assertFalse(self.ledger.verify()["ok"])
        with self.assertRaisesRegex(ValueError, "no longer match"):
            self.ledger.record(self.event(ref, operation={"principal": "anonymous",
                "action": "s3:PutObject", "resource_id": "other-bucket", "method": "PUT"}))

    def test_verify_reports_corrupt_event_snapshot_instead_of_crashing(self):
        ref = self.ref()
        event_id = self.ledger.record(self.event(ref))["event"]
        self.ctx.store.db.execute("UPDATE cloud_events SET data=? WHERE id=?", ("{not-json", event_id))
        self.ctx.store.db.commit()
        result = self.ledger.verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("invalid event snapshot" in issue["reason"]
                            for issue in result["issues"]))

    def test_proof_needs_distinct_marker_control_before_after_cleanup(self):
        ref = self.ref()
        m, control = "bvcloud_owned_001a", "bvcloud_control_02b"
        roles = {"owner-baseline": "good baseline", "test": "observed " + m,
                 "replay": "fresh repeat " + m, "negative-control": "different " + control,
                 "before": "old value", "after": "new value " + m, "cleanup": "restored"}
        files = {role: self.file("evidence/" + role, content) for role, content in roles.items()}
        data = self.event(ref, state="canary-proved", channel="owned-lab", artifacts=files,
                          marker=m, control_marker=control)
        saved = self.ledger.record(data)
        self.assertFalse(saved["finding_promoted"])
        self.assertTrue(self.ledger.verify()["ok"])
        data["artifacts"].pop("cleanup")
        with self.assertRaisesRegex(ValueError, "before/after/cleanup"):
            self.ledger.record(data)
        data["artifacts"]["cleanup"] = "evidence/cleanup"
        self.file("evidence/negative-control", "marker " + m + " " + control)
        with self.assertRaisesRegex(ValueError, "independently present"):
            self.ledger.record(data)
        self.assertFalse(self.ledger.verify()["ok"])

    def test_live_receipt_grants_scope_and_shared_budget_are_not_traffic_enforcement(self):
        ref = self.ref()
        url = "https://app.acme.test/canary"
        event = self.event(ref, state="observed", channel="native", grant="write", requests=1,
                           operation={"principal": "owned-a", "action": "s3:PutObject",
                                      "resource_id": "owned-fixture", "method": "PUT", "request_url": url})
        with self.assertRaisesRegex(ValueError, "request ID"):
            self.ledger.record(event)
        rid = self.ctx.store.record_request("PUT", url, 201, "owned fixture", [], {}, b"marker",
                                            basis="target-http")
        event["request_ids"] = [rid]
        with self.assertRaisesRegex(ValueError, "reviewed rules"):
            self.ledger.record(event)
        self.camp.raw.update({"program_url": "https://program.example/rules", "rules": ["fixture only"],
                              "cloud": {"rules_reviewed": "2026-11-16", "grants": ["write"], "budget": 1}})
        with self.assertRaisesRegex(ValueError, "reviewed rules"):
            self.ledger.record(event)  # PUT is not in policy.allowed_methods
        self.ctx.policy.allowed_methods.append("PUT")
        saved = self.ledger.record(event)
        self.assertFalse(saved["executed"])
        self.assertTrue(self.ledger.record(event)["deduplicated"])
        event["reason"] = "new independent attempt"
        with self.assertRaisesRegex(ValueError, "budget"):
            self.ledger.record(event)
        self.assertEqual(self.ctx.store.network_attempts(), 0)  # fixture record is not a real send

    def test_rejects_ambiguous_context_and_unsafe_paths(self):
        ref = self.ref()
        with self.assertRaisesRegex(ValueError, "exact reference"):
            self.ledger.record(self.event(ref, operation={"principal": "owned-a",
                "action": "s3:PutObject", "resource_id": "other-bucket", "method": "PUT"}))
        with self.assertRaisesRegex(ValueError, "bearer/query"):
            self.ledger.record(self.event(ref, operation={"principal": "owned-a",
                "action": "s3:PutObject", "resource_id": "owned-fixture", "method": "PUT",
                "request_url": "https://app.acme.test/a?sig=private"}))
        with self.assertRaisesRegex(ValueError, "campaign"):
            self.ledger.import_text("../outside.txt")
        with self.assertRaisesRegex(ValueError, "value-free label"):
            self.ledger.record(self.event(ref, operation={"principal": "AKIAABCDEFGHIJKLMNOP",
                "action": "s3:PutObject", "resource_id": "owned-fixture", "method": "PUT"}))
        with self.assertRaisesRegex(ValueError, "symlinks"):
            (self.root / "evidence" / "link").symlink_to(self.root / "evidence" / "app.js")
            self.ledger.import_text("evidence/link")

    def test_config_validation_report_and_cli(self):
        cfg = json.loads((self.root / "scope.json").read_text())
        cfg["cloud"] = {"rules_reviewed": "", "grants": ["chain"], "budget": 0}
        (self.root / "scope.json").write_text(json.dumps(cfg))
        with self.assertRaises(ConfigError):
            Campaign.load(self.root)
        cfg["cloud"] = {}
        (self.root / "scope.json").write_text(json.dumps(cfg))
        self.ref()
        write_reports(self.ctx)
        self.assertIn("Cloud references", (self.root / "recon.md").read_text())
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(["cloud", "plan", str(self.root)]), 0)
        self.assertIn("owned-fixture", stdout.getvalue())
        self.assertNotIn("/canary", stdout.getvalue())  # no object key via plan

    def test_cli_offline_verbs_smoke(self):
        config = json.loads((self.root / "scope.json").read_text())
        config.update({"program_url": "https://program.example/fixture",
                       "rules": ["owned offline wildcard proposal fixture"],
                       "cloud": {"rules_reviewed": "2026-11-16",
                                 "grants": ["discovery"], "budget": 2}})
        config["policy"]["mode"] = "loud"
        (self.root / "scope.json").write_text(json.dumps(config))
        self.file("evidence/refs.txt", "s3://owned-fixture/key")
        self.file("evidence/gen.json", json.dumps({"schema": 1,
            "pattern": "https://{word}.acme.test/", "words": ["old"]}))

        def cli(*args):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = main(["cloud", *args[:1], str(self.root), *args[1:]])
            self.assertEqual(code, 0)
            return json.loads(output.getvalue())

        with patch("socket.socket", side_effect=AssertionError("CLI cloud verbs must be offline")):
            self.assertEqual(cli("import", "--file", "evidence/refs.txt")["references"], 1)
            self.assertEqual(cli("generate", "--file", "evidence/gen.json")["candidate_count"], 1)
            ref = cli("plan")["candidates"][0]["id"]
            self.file("evidence/event.json", json.dumps(self.event(ref, state="blocked")))
            self.assertFalse(cli("record", "--file", "evidence/event.json")["finding_promoted"])
            self.assertEqual(len(cli("show", "--reference", str(ref))["events"]), 1)
            self.assertEqual(cli("status")["generated_candidates"], 1)
            self.assertTrue(cli("verify")["ok"])

    def test_offline_discovery_generation_is_scoped_and_not_queued(self):
        self.camp.raw.update({"program_url": "https://program.example/rules",
                              "rules": ["fixture wildcard and discovery only"],
                              "cloud": {"rules_reviewed": "2026-11-16",
                                        "grants": ["discovery"], "budget": 3}})
        self.ctx.policy.mode = "loud"
        spec = {"schema": 1, "pattern": "https://{word}.acme.test/",
                "words": ["old", "dev", "api"]}
        self.file("evidence/gen.json", json.dumps(spec))
        with patch("socket.socket", side_effect=AssertionError("generation must be offline")):
            result = self.ledger.generate_file("evidence/gen.json")
        self.assertEqual(result["candidate_count"], 3)
        self.assertFalse(result["probe_permitted"])
        self.assertEqual(self.ledger.status()["generated_candidates"], 3)
        self.assertEqual(self.ctx.store.jobs(), [])
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        self.assertTrue(self.ledger.verify()["ok"])
        self.file("evidence/gen.json", "tampered")
        self.assertFalse(self.ledger.verify()["ok"])

    def test_discovery_fails_closed_on_foreign_provider_and_missing_grants(self):
        self.file("evidence/gen.json", json.dumps({"schema": 1,
            "pattern": "https://{word}.acme.test/", "words": ["dev"]}))
        with self.assertRaisesRegex(ValueError, "reviewed discovery"):
            self.ledger.generate_file("evidence/gen.json")
        self.camp.raw.update({"program_url": "https://program.example/rules",
                              "rules": ["fixture wildcard"],
                              "cloud": {"rules_reviewed": "2026-11-16",
                                        "grants": ["discovery"], "budget": 3}})
        self.ctx.policy.mode = "loud"
        self.file("evidence/gen.json", json.dumps({"schema": 1,
            "pattern": "https://{word}.s3.amazonaws.com/", "words": ["team"]}))
        with self.assertRaisesRegex(ValueError, "non-shared program origins"):
            self.ledger.generate_file("evidence/gen.json")
        self.file("evidence/gen.json", json.dumps({"schema": 1,
            "pattern": "https://{word}.elsewhere.test/", "words": ["team"]}))
        with self.assertRaisesRegex(ValueError, "explicit wildcard"):
            self.ledger.generate_file("evidence/gen.json")
        self.file("evidence/gen.json", json.dumps({"schema": 1,
            "pattern": "https://{word}.acme.test/private", "words": ["team"]}))
        with self.assertRaisesRegex(ValueError, "plain hostname patterns"):
            self.ledger.generate_file("evidence/gen.json")


if __name__ == "__main__":
    unittest.main()
