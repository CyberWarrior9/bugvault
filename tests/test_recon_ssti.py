"""Offline SSTI evidence tests; no live requests, template eval or credential use."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.campaign import OutOfScope, scope_template
from recon.cli import main
from recon.fields import FieldLedger
from recon.pipeline import Recon
from recon.report import write_reports
from recon.score import applicable_classes
from recon.ssti import SstiLedger, classify, granted_depths, probes
from tests.test_recon import write_campaign


class SstiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.aid = self.ctx.add_endpoint("https://acme.test/preview", "har", method="POST",
                                         params=["template"])
        self.ctx.store.add_observation(self.aid, "POST", "test-a",
                                       {"body": ["template"], "query": []}, 200, "har")
        FieldLedger(self.ctx).sync(self.aid)
        self.led = SstiLedger(self.ctx)
        self.data = self.led.start(self.aid, "template", "POST", "form", "test-a")
        self.set_id = self.data["set_id"]
        self.surface = self.data["surfaces"][0]["id"]
        self.probes = {p["id"]: p for p in self.data["probes"]}

    def capture(self, probe_id, output, surface=None, complete=True):
        p = self.probes[probe_id]
        self.ctx.store.record_request("POST", "https://acme.test/preview", 200, "test",
                                      [], {}, body=output.encode(), body_complete=complete,
                                      basis="test-fixture", req_body=p["raw"].encode())
        response_id = self.ctx.store.db.execute("SELECT MAX(id) FROM requests").fetchone()[0]
        return self.led.trace(surface or self.surface, probe_id, response_id=response_id)

    def confirm(self):
        for name in ("braces-a", "braces-b", "braces-control"):
            p = self.probes[name]
            output = p["raw"] if name.endswith("control") else \
                p["opening"] + p["expected"] + p["closing"]
            self.capture(name, output)
        self.led.record(self.surface, "confirm", "observed", "Depth prerequisite confirmed")

    def enable_depth(self, grants=("file-read", "execution"),
                     callbacks=("*.callbacks.example.test",)):
        config = {"depth_grants": list(grants), "callback_hosts": list(callbacks)}
        self.ctx.campaign.raw["ssti"] = config
        path = self.root / "scope.json"
        raw = json.loads(path.read_text())
        raw["ssti"] = config
        path.write_text(json.dumps(raw))

    def artifact(self, name, text):
        path = self.root / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return f"evidence/{name}"

    def markers(self):
        return self.led.plan(self.set_id)["depth"]["markers"]

    def test_set_is_idempotent_and_context_bound(self):
        again = self.led.start(self.aid, "template", "POST", "form", "test-a")
        self.assertEqual(again["set_id"], self.set_id)
        self.assertEqual(again["probes"], self.data["probes"])
        with self.assertRaisesRegex(ValueError, "no matching field-ledger"):
            self.led.start(self.aid, "template", "POST", "form", "someone-else")
        with self.assertRaisesRegex(ValueError, "different compact"):
            self.led.start(self.aid, "template", "POST", "form", "test-a", compact=True)
        self.assertEqual(len(again["probes"]), 6)
        self.assertFalse(again["executed"])

    def test_literal_reflection_does_not_confirm_and_incomplete_is_inconclusive(self):
        p = self.probes["braces-a"]
        literal = self.capture("braces-a", p["raw"])
        self.assertEqual(literal["outcome"], "literal")
        self.assertTrue(literal["submission_receipt"])
        self.assertEqual(self.capture("braces-b", p["opening"] + "garbled", complete=False)["outcome"],
                         "inconclusive")
        self.assertEqual(self.led.fingerprint(self.set_id)["surfaces"][0]["families"], [])
        with self.assertRaisesRegex(ValueError, "two distinct"):
            self.led.record(self.surface, "confirm", "observed", "Not proven")
        with self.assertRaisesRegex(ValueError, "every probe"):
            self.led.record(self.surface, "detect", "negative", "Not all captured")

    def test_two_results_control_receipts_and_surface_independence(self):
        for suffix in ("a", "b"):
            p = self.probes[f"braces-{suffix}"]
            self.assertEqual(self.capture(p["id"], p["opening"] + p["expected"] + p["closing"])["outcome"],
                             "evaluated")
        with self.assertRaisesRegex(ValueError, "two distinct"):
            self.led.record(self.surface, "confirm", "observed", "Control missing")
        p = self.probes["braces-control"]
        self.capture(p["id"], p["raw"])
        self.assertEqual(self.led.status(self.set_id)["surfaces"][0]["confirmed_families"], ["braces"])
        self.assertGreater(len(self.led.fingerprint(self.set_id)["surfaces"][0]["engine_candidates"]["braces"]), 1)
        event = self.led.record(self.surface, "confirm", "observed", "Captures are from test account")
        self.assertFalse(event["finding_promoted"])
        field = next(f for f in FieldLedger(self.ctx).show(self.aid, "ssti-eval")["fields"]
                     if f["account"] == "test-a")
        self.assertEqual(field["cases"]["ssti-eval"], "observed")
        export = self.led.add_surface(self.set_id, "export", "owned report")
        self.assertEqual(self.led.status(self.set_id)["surfaces"][1]["confirmed_families"], [])
        with self.assertRaisesRegex(ValueError, "different server-side surface"):
            self.led.record(export["id"], "stored", "observed", "not in export")
        report = next(p for p in write_reports(self.ctx) if p.name == "coverage.md")
        self.assertIn("SSTI input × render-surface", report.read_text())

    def test_dom_only_is_not_server_proof(self):
        dom = self.led.add_surface(self.set_id, "dom", "local preview")
        p = self.probes["braces-a"]
        result = self.capture("braces-a", p["opening"] + p["expected"] + p["closing"], dom["id"])
        self.assertEqual(result["outcome"], "client-evaluated")
        with self.assertRaisesRegex(ValueError, "raw evaluation"):
            self.led.record(dom["id"], "detect", "observed", "DOM only")

    def test_no_receipt_is_not_confirmation(self):
        p = self.probes["braces-a"]
        rid = self.ctx.store.record_request("GET", "https://acme.test/another", 200, "test",
                                            [], {}, body=(p["opening"] + p["expected"] + p["closing"]).encode(),
                                            body_complete=True, basis="fixture")
        result = self.led.trace(self.surface, "braces-a", response_id=rid)
        self.assertEqual(result["outcome"], "evaluated")
        self.assertFalse(result["submission_receipt"])
        with self.assertRaisesRegex(ValueError, "submission receipt"):
            self.led.record(self.surface, "detect", "observed", "Unbound response")
        # A later submission cannot retroactively justify an earlier response.
        self.ctx.store.record_request("POST", "https://acme.test/preview", 200, "test",
                                       [], {}, req_body=p["raw"].encode())
        self.assertFalse(self.led.trace(self.surface, "braces-a", response_id=rid)["submission_receipt"])
        self.assertTrue(self.led.verify()["verified"])
        self.assertEqual(self.led.status(self.set_id)["surfaces"][0]["evaluated_families"], [])

    def test_unrelated_response_does_not_borrow_another_submission(self):
        p = self.probes["braces-a"]
        text = (p["opening"] + p["expected"] + p["closing"]).encode()
        self.ctx.store.record_request("POST", "https://acme.test/preview", 200, "test",
                                      [], {}, body=b"queued", body_complete=True,
                                      req_body=p["raw"].encode())
        unrelated = self.ctx.store.record_request(
            "POST", "https://acme.test/preview", 200, "test", [], {}, body=text,
            body_complete=True, req_body=b"another field or account")
        result = self.led.trace(self.surface, "braces-a", response_id=unrelated)
        self.assertEqual(result["outcome"], "evaluated")
        self.assertFalse(result["submission_receipt"])
        view = self.led.add_surface(self.set_id, "view", "later view")
        self.assertTrue(self.led.trace(view["id"], "braces-a",
                                       response_id=unrelated)["submission_receipt"])
        # A view receipt is a temporal correlation, not proof of account ownership.

    def test_raw_entity_encoded_output_and_tampered_classification_are_not_proofs(self):
        p = self.probes["braces-a"]
        encoded = "".join(f"&#{ord(c)};" for c in p["expected"])
        self.assertEqual(classify(p, (p["opening"] + encoded + p["closing"]).encode()), "altered")
        result = self.capture("braces-a", p["opening"] + encoded + p["closing"])
        self.assertEqual(result["outcome"], "altered")
        self.ctx.store.db.execute("UPDATE ssti_observations SET outcome='evaluated' WHERE id=?",
                                  (result["observation_id"],))
        self.ctx.store.db.commit()
        self.assertFalse(self.led.verify(self.set_id)["verified"])
        self.assertEqual(self.led.status(self.set_id)["surfaces"][0]["evaluated_families"], [])

    def test_bodyless_response_stays_inconclusive_without_integrity_failure(self):
        p = self.probes["braces-a"]
        rid = self.ctx.store.record_request("POST", "https://acme.test/preview", 202,
                                             "test", [], {}, body_complete=True,
                                             req_body=p["raw"].encode())
        self.assertEqual(self.led.trace(self.surface, p["id"], response_id=rid)["outcome"],
                         "inconclusive")
        self.assertTrue(self.led.verify(self.set_id)["verified"])

    def test_context_matching_does_not_mix_query_and_body(self):
        self.ctx.store.add_observation(
            self.aid, "POST", "test-a", {"query": ["template"], "body": []}, 200,
            "har", capture_key="query-context",
            context={"role": "query", "tenant": "t", "workflow_state": "search"})
        FieldLedger(self.ctx).sync(self.aid)
        self.assertEqual(self.led.start(self.aid, "template", "POST", "form", "test-a")["set_id"],
                         self.set_id)
        with self.assertRaisesRegex(ValueError, "role/tenant/workflow"):
            self.led.start(self.aid, "template", "POST", "form", "test-a",
                           role="query", tenant="t", workflow="search")
        query = self.led.start(self.aid, "template", "POST", "query", "test-a",
                               role="query", tenant="t", workflow="search")
        self.assertNotEqual(query["set_id"], self.set_id)

    def test_labelled_submission_from_another_account_is_not_a_receipt(self):
        p = self.probes["braces-a"]
        body = (p["opening"] + p["expected"] + p["closing"]).encode()
        wrong = self.ctx.store.record_request(
            "POST", "https://acme.test/preview", 200, "imported", [], {},
            body=body, body_complete=True, req_body=p["raw"].encode(),
            context={"account": "other", "role": ""})
        self.assertFalse(self.led.trace(self.surface, p["id"], response_id=wrong)["submission_receipt"])
        right = self.ctx.store.record_request(
            "POST", "https://acme.test/preview", 200, "imported", [], {},
            body=body, body_complete=True, req_body=p["raw"].encode(),
            context={"account": "test-a", "role": ""})
        self.assertTrue(self.led.trace(self.surface, p["id"], response_id=right)["submission_receipt"])

    def test_receipt_tampering_invalidates_observation(self):
        p = self.probes["braces-a"]
        result = self.capture("braces-a", p["opening"] + p["expected"] + p["closing"])
        rid = result["receipt_request_id"]
        payload = self.ctx.store.request_payload(rid)
        (self.ctx.store.bodies_dir / payload["body_sha256"]).write_bytes(b"changed")
        self.assertFalse(self.led.verify()["verified"])
        self.assertEqual(self.led.status(self.set_id)["surfaces"][0]["evaluated_families"], [])
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.led.record(self.surface, "detect", "observed", "No longer valid")

    def test_artifact_hash_and_scope(self):
        p = self.probes["braces-a"]
        path = self.root / "evidence" / "mail.txt"
        path.parent.mkdir()
        path.write_text(p["opening"] + p["expected"] + p["closing"])
        mail = self.led.add_surface(self.set_id, "email", "owned test mailbox")
        self.led.trace(mail["id"], "braces-a", artifact="evidence/mail.txt")
        self.assertTrue(self.led.verify()["verified"])
        path.write_text("changed")
        self.assertFalse(self.led.verify()["verified"])
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.led.record(mail["id"], "detect", "inconclusive", "changed")
        with self.assertRaisesRegex(ValueError, "inside the campaign"):
            self.led.trace(mail["id"], "braces-b", artifact="../outside.txt")

    def test_negative_requires_literal_probes_on_one_surface(self):
        for p in self.probes.values():
            self.capture(p["id"], p["raw"])
        self.assertTrue(self.led.status(self.set_id)["surfaces"][0]["negative"])
        self.led.record(self.surface, "detect", "negative", "All probes reflected literally")
        new = self.led.add_surface(self.set_id, "async", "job not captured")
        self.assertFalse(next(s for s in self.led.status(self.set_id)["surfaces"]
                              if s["surface_id"] == new["id"])["negative"])

    def test_cli_dispatch_and_tiered_seeding(self):
        for path, params, tier in (("/preview", ["template"], "tier 1"),
                                   ("/export", ["title"], "tier 2"),
                                   ("/comments", ["text"], "tier 3")):
            result = applicable_classes({"value": "https://acme.test" + path,
                                         "attrs": {"params": params}})
            self.assertIn(tier, result["ssti"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["ssti", "status", str(self.root), "--set", str(self.set_id)]), 0)
        self.assertIn('"surfaces"', output.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["ssti", "verify", str(self.root)]), 0)

    def test_role_tenant_workflow_contexts_do_not_pool(self):
        self.ctx.store.add_observation(
            self.aid, "POST", "test-a", {"body": ["template"], "query": []}, 200,
            "har", capture_key="admin-context",
            context={"role": "admin", "tenant": "test-tenant", "workflow_state": "preview"})
        self.ctx.store.set_coverage(self.aid, "ssti", "tested", "legacy coarse claim")
        report = next(p for p in write_reports(self.ctx) if p.name == "coverage.md").read_text()
        self.assertIn("role=admin", report)
        self.assertIn("field gaps", report)
        with self.assertRaisesRegex(ValueError, "role/tenant/workflow"):
            self.led.start(self.aid, "template", "POST", "form", "test-a", role="admin")
        second = self.led.start(self.aid, "template", "POST", "form", "test-a",
                                role="admin", tenant="test-tenant", workflow="preview")
        self.assertNotEqual(second["set_id"], self.set_id)
        self.assertNotEqual(second["probes"][0]["raw"], self.data["probes"][0]["raw"])
        self.assertEqual(second["role"], "admin")
        self.assertEqual(self.led.status(second["set_id"])["surfaces"][0]["confirmed_families"], [])
        # Confirming the first context cannot close the new context's field coverage.
        for name in ("braces-a", "braces-b", "braces-control"):
            p = self.probes[name]
            text = p["raw"] if name.endswith("control") else p["opening"] + p["expected"] + p["closing"]
            self.capture(name, text)
        self.led.record(self.surface, "confirm", "observed", "First context only")
        state = next(f for f in FieldLedger(self.ctx).show(self.aid, "ssti-eval")["fields"]
                     if f["account"] == "test-a")["cases"]["ssti-eval"]
        self.assertEqual(state, "probed")
        new_surface = second["surfaces"][0]["id"]
        for p in second["probes"]:
            if p["family"] != "braces":
                continue
            output = p["raw"] if p["variant"] == "control" else p["opening"] + p["expected"] + p["closing"]
            rid = self.ctx.store.record_request(
                "POST", "https://acme.test/preview", 200, "test", [], {}, body=output.encode(),
                body_complete=True, basis="owned-fixture", req_body=p["raw"].encode())
            self.led.trace(new_surface, p["id"], response_id=rid)
        self.led.record(new_surface, "confirm", "observed", "Second context")
        state = next(f for f in FieldLedger(self.ctx).show(self.aid, "ssti-eval")["fields"]
                     if f["account"] == "test-a")["cases"]["ssti-eval"]
        self.assertEqual(state, "observed")

    def test_report_exposes_field_gaps_and_coarse_conflicts(self):
        other = self.ctx.add_endpoint("https://acme.test/export", "har", method="POST",
                                      params=["title"])
        self.ctx.store.add_observation(other, "POST", "test-a",
                                       {"body": ["title"], "query": []}, 200, "har")
        FieldLedger(self.ctx).sync(other)
        self.ctx.store.set_coverage(other, "ssti", "refuted", "old coarse claim")
        report = next(p for p in write_reports(self.ctx) if p.name == "coverage.md").read_text()
        self.assertIn("SSTI inputs without a probe set", report)
        self.assertIn("form:title", report)
        self.assertIn("Coarse SSTI rows contradicted", report)
        self.assertIn("refuted", report)

    def test_evaluation_severity_is_capped_and_recorded(self):
        with self.assertRaisesRegex(ValueError, "confirmed raw evaluation"):
            self.led.record(self.surface, "severity-gate", "observed", "premature",
                            severity="medium")
        for name in ("braces-a", "braces-b", "braces-control"):
            p = self.probes[name]
            output = p["raw"] if name.endswith("control") else p["opening"] + p["expected"] + p["closing"]
            self.capture(name, output)
        with self.assertRaisesRegex(ValueError, "medium severity ceiling"):
            self.led.record(self.surface, "severity-gate", "observed", "arithmetic only",
                            severity="critical")
        result = self.led.record(self.surface, "severity-gate", "observed", "arithmetic only",
                                 severity="medium")
        self.assertEqual(result["severity_ceiling"], "medium")
        self.assertFalse(result["finding_promoted"])
        self.assertEqual(self.led.status(self.set_id)["surfaces"][0]["events"][0]["severity"], "medium")
        with self.assertRaisesRegex(ValueError, "only to severity-gate"):
            self.led.record(self.surface, "confirm", "observed", "wrong flag", severity="low")

    def test_cred_read_token_use_and_lateral_raise_the_gated_ceiling(self):
        self.confirm()
        evidence = self.artifact("cred.txt", "path=.env\nDB_PASSWORD=[REDACTED]\n")
        control = self.artifact("cred-control.txt", "path=.env\nDB_PASSWORD=absent\n")
        with self.assertRaisesRegex(ValueError, "ssti.depth_grants"):
            self.led.record(self.surface, "cred-read", "observed", "No grant", grant="file-read",
                            target=".env", attempts=1, artifacts=[evidence, control])
        self.enable_depth(grants=("file-read",))
        read = self.led.record(self.surface, "cred-read", "observed",
                               "Redacted .env excerpt plus control", grant="file-read",
                               target=".env", attempts=1, artifacts=[evidence, control])
        self.assertEqual(read["severity_ceiling"], "high")
        self.assertEqual(len(read["artifacts"]), 2)
        self.assertTrue(all(a["path"].startswith(".recon/ssti-evidence/")
                            for a in read["artifacts"]))
        self.led.record(self.surface, "severity-gate", "observed", "Read rung proven",
                        severity="high")
        with self.assertRaisesRegex(ValueError, "ceiling"):
            self.led.record(self.surface, "severity-gate", "observed", "Too high",
                            severity="critical")

        marker = self.markers()["token-use"]
        target = f"https://acme.test/internal?marker={marker}"
        token_artifact = self.artifact("token.txt", "status=403\nvalue=[REDACTED]\n")
        with self.assertRaisesRegex(ValueError, "execution"):
            self.led.record(self.surface, "token-use", "observed", "No execution grant",
                            grant="execution", target=target, exercise="GET", attempts=1,
                            artifacts=[token_artifact])
        self.enable_depth(grants=("file-read", "execution"))
        used = self.led.record(self.surface, "token-use", "observed",
                               "One read-only GET with a redacted response", grant="execution",
                               target=target, exercise="GET", attempts=1,
                               artifacts=[token_artifact])
        self.assertEqual(used["severity_ceiling"], "critical")
        self.led.record(self.surface, "severity-gate", "observed", "Execution rung proven",
                        severity="critical")

        marker = self.markers()["lateral"]
        host = f"{marker}.callbacks.example.test"
        oob = self.artifact("oob.txt", f"query host={host}\n")
        lateral = self.led.record(self.surface, "lateral", "observed",
                                  "Approved receiver outside the render origin", grant="execution",
                                  target=host, attempts=1, artifacts=[oob])
        self.assertEqual(lateral["severity_ceiling"], "critical")
        self.assertTrue(self.led.verify()["verified"])
        stored = next((self.root / ".recon" / "ssti-evidence").iterdir())
        stored.write_text("tampered")
        self.assertFalse(self.led.verify()["verified"])
        status = self.led.status(self.set_id)
        self.assertEqual(status["surfaces"][0]["depth_cases"], [])
        self.assertIsNone(status["surfaces"][0]["severity_ceiling"])

    def test_depth_targets_methods_and_redaction_are_enforced(self):
        self.confirm()
        self.enable_depth()
        marker = self.markers()["token-use"]
        target = f"https://acme.test/internal?marker={marker}"
        redacted = self.artifact("redacted.txt", "value=[REDACTED]\n")
        secret = self.artifact("secret.txt", "AKIAFAKEFORTEST\n")
        evidence = self.artifact("evidence.txt", "path=.env\nDB_PASSWORD=[REDACTED]\n")
        control = self.artifact("control.txt", "path=.env\nDB_PASSWORD=absent\n")
        with self.assertRaisesRegex(ValueError, "listed data path"):
            self.led.record(self.surface, "cred-read", "observed", "Wrong path",
                            grant="file-read", target="notes.txt", attempts=1,
                            artifacts=[evidence, control])
        with self.assertRaisesRegex(ValueError, "distinct evidence"):
            self.led.record(self.surface, "cred-read", "observed", "No control",
                            grant="file-read", target=".env", attempts=1, artifacts=[evidence])
        with self.assertRaisesRegex(ValueError, "unredacted secret"):
            self.led.record(self.surface, "cred-read", "observed", "Secret present",
                            grant="file-read", target=".env", attempts=1,
                            artifacts=[evidence, secret])
        self.led.record(self.surface, "cred-read", "observed", "Credential excerpt",
                        grant="file-read", target=".env", attempts=1,
                        artifacts=[evidence, control])
        with self.assertRaisesRegex(ValueError, "read-only"):
            self.led.record(self.surface, "token-use", "observed", "POST is not read-only",
                            grant="execution", target=target, exercise="POST", attempts=1,
                            artifacts=[redacted])
        with self.assertRaisesRegex(ValueError, "0 or 1"):
            self.led.record(self.surface, "token-use", "observed", "Too many attempts",
                            grant="execution", target=target, exercise="GET", attempts=2,
                            artifacts=[redacted])
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.led.record(self.surface, "token-use", "observed", "No attempt",
                            grant="execution", target=target, exercise="GET", attempts=0,
                            artifacts=[redacted])
        with self.assertRaisesRegex(ValueError, "attempt marker"):
            self.led.record(self.surface, "token-use", "observed", "No marker",
                            grant="execution", target="https://acme.test/internal",
                            exercise="GET", attempts=1, artifacts=[redacted])
        with self.assertRaisesRegex(ValueError, "credential-named query"):
            self.led.record(self.surface, "token-use", "observed", "Credential in URL",
                            grant="execution", target=f"https://acme.test/?token={marker}",
                            exercise="GET", attempts=1, artifacts=[redacted])
        with self.assertRaises(OutOfScope):
            self.led.record(self.surface, "token-use", "observed", "Out of scope",
                            grant="execution", target=f"https://evil.test/?m={marker}",
                            exercise="GET", attempts=1, artifacts=[redacted])
        self.led.record(self.surface, "token-use", "observed", "Read-only exercise",
                        grant="execution", target=target, exercise="GET", attempts=1,
                        artifacts=[redacted])

        self.enable_depth(callbacks=("*.callbacks.example.test", "callbacks.example.test",
                                     "*.acme.test"))
        lateral_marker = self.markers()["lateral"]
        with self.assertRaisesRegex(ValueError, "no explicit"):
            self.led.record(self.surface, "lateral", "observed", "Unapproved receiver",
                            grant="execution", target=f"{lateral_marker}.evil.test",
                            attempts=1, artifacts=[redacted])
        with self.assertRaisesRegex(ValueError, "must differ"):
            self.led.record(self.surface, "lateral", "observed", "Same origin",
                            grant="execution", target=f"{lateral_marker}.acme.test",
                            attempts=1, artifacts=[redacted])
        with self.assertRaisesRegex(ValueError, "attempt marker"):
            self.led.record(self.surface, "lateral", "observed", "No marker",
                            grant="execution", target="callbacks.example.test",
                            attempts=1, artifacts=[redacted])
        with self.assertRaisesRegex(ValueError, "bound attempt marker"):
            self.led.record(self.surface, "lateral", "observed", "Artifact unbound",
                            grant="execution", target=f"{lateral_marker}.callbacks.example.test",
                            attempts=1, artifacts=[redacted])
        oob = self.artifact("oob-lateral.txt",
                            f"query host={lateral_marker}.callbacks.example.test\n")
        self.led.record(self.surface, "lateral", "observed", "Approved receiver",
                        grant="execution", target=f"{lateral_marker}.callbacks.example.test",
                        attempts=1, artifacts=[oob])

    def test_depth_prerequisites_are_ordered(self):
        self.confirm()
        self.enable_depth()
        redacted = self.artifact("redacted.txt", "value=[REDACTED]\n")
        marker = self.markers()["token-use"]
        with self.assertRaisesRegex(ValueError, "cred-read"):
            self.led.record(self.surface, "token-use", "observed", "No credential read",
                            grant="execution", target=f"https://acme.test/?m={marker}",
                            exercise="GET", attempts=1, artifacts=[redacted])
        evidence = self.artifact("evidence.txt", "path=.env\nvalue=[REDACTED]\n")
        control = self.artifact("control.txt", "path=.env\nvalue=absent\n")
        self.led.record(self.surface, "cred-read", "observed", "Credential read",
                        grant="file-read", target=".env", attempts=1,
                        artifacts=[evidence, control])
        lateral_marker = self.markers()["lateral"]
        oob = self.artifact("oob.txt", f"host={lateral_marker}.callbacks.example.test\n")
        with self.assertRaisesRegex(ValueError, "token-use"):
            self.led.record(self.surface, "lateral", "observed", "No token use",
                            grant="execution",
                            target=f"{lateral_marker}.callbacks.example.test", attempts=1,
                            artifacts=[oob])

    def test_depth_config_and_callback_fallback_fail_closed(self):
        self.assertEqual(granted_depths({}), set())
        self.assertEqual(granted_depths({"depth_grants": ["all"]}),
                         {"context", "file-read", "execution"})
        for bad in ({"depth_grants": ["nope"]},
                    {"depth_grants": ["file-read", "file-read"]},
                    {"depth_grants": "file-read"}):
            with self.assertRaises(ValueError):
                granted_depths(bad)
        self.ctx.campaign.raw["ssti"] = {"depth_grants": [],
                                         "callback_hosts": ["*.callbacks.example.test"]}
        self.assertTrue(self.led.plan(self.set_id)["depth"]["callback_hosts_configured"])
        self.ctx.campaign.raw["ssti"] = {"depth_grants": [], "callback_hosts": ["not a host"]}
        with self.assertRaisesRegex(ValueError, "callback_hosts"):
            self.led._callback_hosts()
        self.ctx.campaign.raw["ssti"] = {"depth_grants": []}
        self.ctx.campaign.raw["ssrf"] = {"callback_hosts": ["*.oob.example.test"]}
        self.assertTrue(self.led.plan(self.set_id)["depth"]["callback_hosts_configured"])
        template = scope_template("lab", ["example.com"], "passive")
        self.assertEqual(template["ssti"]["depth_grants"], [])
        self.assertIn("file-read", template["ssti"]["_depth_grants_help"])
        self.assertIn("callback_hosts", template["ssti"])

    def test_cli_depth_record_flags(self):
        self.confirm()
        self.enable_depth(grants=("file-read",))
        evidence = self.artifact("cli-evidence.txt", "path=.env\nvalue=[REDACTED]\n")
        control = self.artifact("cli-control.txt", "path=.env\nvalue=absent\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = main(["ssti", "record", str(self.root), "--surface", str(self.surface),
                       "--case", "cred-read", "--state", "observed", "--note",
                       "CLI credential read", "--grant", "file-read", "--target", ".env",
                       "--attempts", "1", "--artifact", evidence, "--artifact", control])
        self.assertEqual(rc, 0)
        self.assertIn('"severity_ceiling": "high"', output.getvalue())
        self.assertIn('"grant": "file-read"', output.getvalue())


class SstiMigrationTests(unittest.TestCase):
    def test_collision_seed_still_produces_distinct_confirmation_results(self):
        # This seed's first two braces products collided before the tie-breaker.
        minted = probes("collision-34338")
        self.assertNotEqual(minted["braces-a"]["expected"], minted["braces-b"]["expected"])

    def test_legacy_sets_keep_ids_and_surface_references(self):
        with tempfile.TemporaryDirectory() as directory:
            camp = write_campaign(Path(directory) / "camp", "active", [], in_scope=["acme.test"])
            ctx = Recon(camp, log=lambda _: None)
            try:
                aid = ctx.add_endpoint("https://acme.test/preview", "har", method="POST",
                                       params=["template"])
                db = ctx.store.db
                db.executescript("""
CREATE TABLE ssti_sets(id INTEGER PRIMARY KEY,asset_id INTEGER,method TEXT,location TEXT,
field TEXT,account TEXT,seed TEXT UNIQUE,compact INTEGER,created TEXT,
UNIQUE(asset_id,method,location,field,account));
CREATE TABLE ssti_surfaces(id INTEGER PRIMARY KEY,set_id INTEGER REFERENCES ssti_sets(id),
kind TEXT,label TEXT,created TEXT,UNIQUE(set_id,kind,label));
CREATE TABLE ssti_observations(id INTEGER PRIMARY KEY,surface_id INTEGER REFERENCES ssti_surfaces(id),
probe_id TEXT,source_kind TEXT,source_ref TEXT,sha256 TEXT,outcome TEXT,receipt INTEGER,created TEXT);
CREATE TABLE ssti_case_events(id INTEGER PRIMARY KEY,surface_id INTEGER REFERENCES ssti_surfaces(id),
case_id TEXT,state TEXT,note TEXT,created TEXT);
""")
                db.execute("INSERT INTO ssti_sets VALUES(1,?,?,?,?,?,?,0,'now')",
                           (aid, "POST", "form", "template", "test-a", "0123456789abcdef"))
                db.execute("INSERT INTO ssti_surfaces VALUES(9,1,'response','submission','now')")
                db.execute("INSERT INTO ssti_observations VALUES(7,9,'braces-a','response','42',"
                           "'hash','inconclusive',0,'now')")
                db.execute("INSERT INTO ssti_case_events VALUES(5,9,'detect','blocked','old event','now')")
                db.commit()
                ledger = SstiLedger(ctx)
                self.assertEqual(ledger.probes(1)["surfaces"][0]["id"], 9)
                self.assertEqual(ledger.probes(1)["role"], "")
                self.assertIsNone(db.execute("PRAGMA foreign_key_check").fetchone())
                self.assertEqual(db.execute("SELECT surface_id FROM ssti_observations WHERE id=7")
                                 .fetchone()[0], 9)
                self.assertEqual(tuple(db.execute(
                    "SELECT severity,grant,target,exercise,attempts FROM ssti_case_events WHERE id=5")
                    .fetchone()), ("", "", "", "", 0))
                self.assertEqual(db.execute("SELECT COUNT(*) FROM ssti_event_artifacts")
                                 .fetchone()[0], 0)
                self.assertEqual(db.execute("PRAGMA foreign_keys").fetchone()[0], 1)
                self.assertEqual(ledger.add_surface(1, "export", "test")["set_id"], 1)
                self.assertEqual(SstiLedger(ctx).probes(1)["set_id"], 1)
            finally:
                ctx.store.close()


if __name__ == "__main__":
    unittest.main()
