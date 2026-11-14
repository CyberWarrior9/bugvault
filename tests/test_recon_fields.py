"""Field ledger: per-field per-case coverage, trigger-matrix gate, canary map,
context packets, payload attribution and blind-XSS bundle validation. All offline."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.fields import (CASES_BY_CLASS, FieldLedger, infer_trigger, mint_marker,
                          module_of)
from recon.pipeline import Recon
from recon.score import applicable_classes
from tests.test_recon import write_campaign


class FieldFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.aid = self.ctx.add_endpoint(
            "https://acme.test/profile/314", "har", method="POST",
            params=["firstName", "bio", "q", "template"], extra={"id_params": []})
        self.ctx.store.add_observation(
            self.aid, "POST", "alice",
            {"query": ["q"], "body": ["firstName", "bio", "template"], "ids": {},
             "auth": True}, 200, "har", capture_key="h:1:0",
            context={"basis": "captured-real-traffic", "account": "alice", "role": "user",
                     "workflow_state": "edit"})
        self.led = FieldLedger(self.ctx)
        self.module = module_of(self.led._asset(self.aid)["value"])

    def write_body(self, body: bytes) -> None:
        self.camp.bodies_dir.mkdir(parents=True, exist_ok=True)
        (self.camp.bodies_dir / hashlib.sha256(body).hexdigest()).write_bytes(body)

    def store_roundtrip(self, marker: str) -> int:
        """One stored request whose request body and response body carry the marker."""
        resp = b"<div>saved: " + marker.encode() + b"</div>"
        req = b"bio=" + marker.encode() + b"&q=1"
        rid = self.ctx.store.record_request(
            "POST", "https://acme.test/profile/314", 200, "test", ["cookie"],
            {"Content-Type": "text/html"}, body=resp, body_complete=True, basis="test")
        self.ctx.store.db.execute(
            "INSERT INTO request_payload(request_id, body_sha256, body_len, content_type)"
            " VALUES(?,?,?,?)", (rid, hashlib.sha256(req).hexdigest(), len(req),
                                 "application/x-www-form-urlencoded"))
        self.ctx.store.db.commit()
        self.write_body(req)
        return rid


class SyncTests(FieldFixture):
    def test_sync_seeds_rows_for_applicable_cases_only(self):
        classes = applicable_classes(self.led._asset(self.aid))
        self.assertIn("html-injection", classes)   # firstName/bio content fields
        self.assertIn("ssti", classes)             # template field
        result = self.led.sync(self.aid)
        self.assertEqual(set(result["cases"]),
                         {"xss-reflected", "xss-stored", "xss-dom", "xss-blind",
                          "htmli-structure", "ssti-eval", "sqli-error", "sqli-boolean",
                          "sqli-time", "sqli-oob", "sqli-union", "sqli-second-order",
                          "idor-read", "idor-write", "fileread-path", "massassign-role",
                          "csrf-state"})
        self.assertEqual(result["cases"], list(
            CASES_BY_CLASS["xss"] + CASES_BY_CLASS["html-injection"]
            + CASES_BY_CLASS["sqli"] + CASES_BY_CLASS["ssti"]
            + CASES_BY_CLASS["idor-bola"] + CASES_BY_CLASS["file-read"]
            + CASES_BY_CLASS["mass-assignment"] + CASES_BY_CLASS["csrf"]))
        self.assertEqual(result["fields"], 4)
        # a field may appear in several discovery contexts (here: one observation row
        # plus one merged-attrs row); every context seeds its own ledger rows
        self.assertEqual(result["rows_added"], 2 * result["fields"] * len(result["cases"]))
        self.assertIn("hidden parameters are never guessed", result["basis"])
        self.assertFalse(result["executed"])
        again = self.led.sync(self.aid)
        self.assertEqual(again["rows_added"], 0)  # idempotent
        self.assertIn("discovered inputs only", again["basis"])

    def test_record_and_show_update_cases(self):
        self.led.sync(self.aid)
        result = self.led.record(self.aid, "bio", "xss-stored", "observed", method="POST",
                                 location="form", account="alice", note="rendered unencoded",
                                 model="deepseek-v4.1-flash")
        self.assertEqual(result["model"], "deepseek-v4.1-flash")
        show = self.led.show(self.aid, case="xss-stored")
        bio = next(f for f in show["fields"]
                   if f["field"] == "bio" and f["method"] == "POST")
        self.assertEqual(bio["cases"]["xss-stored"], "observed")
        self.assertEqual(bio["note"], "rendered unencoded")
        # recording an unknown case or state is refused
        with self.assertRaises(ValueError):
            self.led.record(self.aid, "bio", "not-a-case", "observed")
        with self.assertRaises(ValueError):
            self.led.record(self.aid, "bio", "xss-stored", "wild-guess")


class TriggerMatrixTests(FieldFixture):
    def test_infer_trigger_shapes(self):
        self.assertEqual(infer_trigger("GET", "https://x.test/api/users", []), "list")
        self.assertEqual(infer_trigger("GET", "https://x.test/s", ["q"]), "search")
        self.assertEqual(infer_trigger("GET", "https://x.test/items", ["status"]), "filter")
        self.assertEqual(infer_trigger("GET", "https://x.test/items", ["sort", "_dir"]), "sort")
        self.assertEqual(infer_trigger("POST", "https://x.test/api/users", ["name"]), "create")
        self.assertEqual(infer_trigger("PATCH", "https://x.test/api/users/7", ["name"]), "edit")
        self.assertEqual(infer_trigger("POST", "https://x.test/api/users/bulk", ["ids"]), "bulk")
        self.assertEqual(infer_trigger("GET", "https://x.test/api/export", ["format"]), "export")
        self.assertEqual(infer_trigger("GET", "https://x.test/api/report/download", []), "export")

    def test_module_of_skips_prefix_and_ids(self):
        self.assertEqual(module_of("https://x.test/api/v2/users/314/orders/9"), "users/orders")
        self.assertEqual(module_of("https://x.test/"), "root")

    def test_observed_on_incomplete_module_stamps_partial(self):
        self.led.sync(self.aid)
        result = self.led.record(self.aid, "q", "xss-reflected", "observed", method="GET",
                                 location="query", account="alice")
        gate = result["coverage_gate"]
        self.assertEqual(gate["module"], self.module)
        self.assertFalse(gate["complete"])
        self.assertEqual(gate["claim"], "partial")
        matrix = self.led.matrix(self.module)
        self.assertEqual(matrix["claim"], "partial")
        self.assertIn("edit", matrix["triggers"])  # POST /profile/{id} maps to edit
        self.assertEqual(matrix["triggers"]["edit"]["state"], "captured")

    def test_full_claim_refused_until_matrix_complete(self):
        self.led.sync(self.aid)
        with self.assertRaises(ValueError) as caught:
            self.led.claim(self.module, "full")
        self.assertIn("trigger cells are missing", str(caught.exception))
        # partial claims are always allowed
        self.led.claim(self.module, "partial")
        # mark every still-missing trigger n-a with a reason, then full is accepted
        for trigger in self.led.matrix(self.module)["missing"]:
            self.led.set_na(self.module, trigger, "module has no such operation")
        self.led.claim(self.module, "full")
        self.assertEqual(self.led.matrix(self.module)["claim"], "full")
        # n-a requires a reason
        with self.assertRaises(ValueError):
            self.led.set_na(self.module, "sort", "")

    def test_claims_rows_render_missing_cells(self):
        self.led.record(self.aid, "q", "xss-reflected", "observed", method="GET",
                        location="query")
        rows = self.led.claims_rows()
        row = next(r for r in rows if r[0] == self.module)
        self.assertEqual(row[1], "partial")
        self.assertTrue(row[2])  # missing triggers listed


class CanaryTests(FieldFixture):
    def test_canary_mints_unique_markers(self):
        first = self.led.canary(self.aid, "bio", method="POST", location="form",
                                account="alice")
        second = self.led.canary(self.aid, "bio", method="POST", location="form",
                                 account="alice")
        self.assertRegex(first["marker"], r"^bv_[0-9a-f]{8}$")
        self.assertNotEqual(first["marker"], second["marker"])
        self.assertIn("dedicated browser", first["how"])
        self.assertFalse(first["executed"])

    def test_trace_finds_surfaces_and_is_idempotent(self):
        marker = self.led.canary(self.aid, "bio", method="POST", location="form")["marker"]
        rid = self.store_roundtrip(marker)
        result = self.led.trace(marker)
        self.assertEqual(result["marker"], marker)
        self.assertEqual(result["requests_scanned"], 1)
        surfaces = {e["surface"] for e in result["events"]}
        self.assertIn("submission-capture", surfaces)
        self.assertIn("same-response", surfaces)
        req_event = next(e for e in result["events"] if e["surface"] == "submission-capture")
        self.assertEqual(req_event["request_id"], rid)
        self.assertEqual(req_event["encoding"], "raw")
        again = self.led.trace(marker)
        self.assertEqual(again["newly_recorded"], 0)
        self.assertIn("not a vulnerability verdict", again["basis"])
        with self.assertRaises(ValueError):
            self.led.trace("bv_00000000")

    def test_trace_labels_export_surfaces_by_content_type(self):
        marker = self.led.canary(self.aid, "bio")["marker"]
        resp = b"bio," + marker.encode()
        rid = self.ctx.store.record_request(
            "GET", "https://acme.test/export/314", 200, "test", [],
            {"Content-Type": "text/csv"}, body=resp, body_complete=True, basis="test")
        self.write_body(resp)
        result = self.led.trace(marker)
        self.assertIn("export-csv", result["surfaces"])

    def test_trace_reports_stripped_when_marker_absent_from_same_response(self):
        marker = self.led.canary(self.aid, "bio")["marker"]
        req = b"bio=" + marker.encode()
        resp = b"<div>sanitized</div>"
        rid = self.ctx.store.record_request(
            "POST", "https://acme.test/profile/314", 200, "test", [], {},
            body=resp, body_complete=True, basis="test")
        self.ctx.store.db.execute(
            "INSERT INTO request_payload(request_id, body_sha256, body_len, content_type)"
            " VALUES(?,?,?,?)", (rid, hashlib.sha256(req).hexdigest(), len(req), None))
        self.ctx.store.db.commit()
        self.write_body(req)
        result = self.led.trace(marker)
        stripped = [e for e in result["events"] if e["encoding"] == "stripped"]
        self.assertTrue(stripped)
        self.assertIn("same-response", result["surfaces"])


class PacketTests(FieldFixture):
    def setup_complete_context(self):
        from recon.waf import WAFProfiles
        self.led.sync(self.aid)
        marker = self.led.canary(self.aid, "bio", method="POST", location="form")["marker"]
        self.store_roundtrip(marker)
        self.led.trace(marker)
        self.led.fingerprint(self.aid, "db", "MySQL via error message")
        self.led.fingerprint(self.aid, "csp", "default-src 'self'")
        waf = WAFProfiles(self.ctx)
        waf.record("acme.test", "<", "char", outcome="blocked", location="form")
        waf.record("acme.test", "'", "char", outcome="allowed", location="form")

    def test_packet_refuses_incomplete_context(self):
        self.led.sync(self.aid)
        with self.assertRaises(ValueError) as caught:
            self.led.packet(self.aid, "bio", "xss-stored")
        message = str(caught.exception)
        for key in ("context_map", "surviving_chars", "blocked_elements",
                    "db_fingerprint", "csp", "waf_ref", "canary_ref"):
            self.assertIn(key, message)

    def test_packet_builds_and_attribution_stamps(self):
        self.setup_complete_context()
        packet = self.led.packet(self.aid, "bio", "xss-stored")
        self.assertEqual(packet["schema_version"], 1)
        self.assertEqual(packet["field"], "bio")
        self.assertEqual(packet["location"], "form")
        self.assertEqual(packet["account"], "alice")
        self.assertTrue(packet["context_map"])
        self.assertIn("<", packet["blocked_elements"])
        self.assertIn("'", packet["surviving_chars"])
        self.assertEqual(packet["db_fingerprint"], "MySQL via error message")
        self.assertEqual(packet["csp"], "default-src 'self'")
        self.assertIn("GET", packet["method_grants"])
        self.assertTrue(packet["waf_ref"].startswith("acme.test@"))
        self.assertRegex(packet["canary_ref"], r"^bv_[0-9a-f]{8}$")
        self.assertFalse(packet["executed"])
        stable = self.led.packet(self.aid, "bio", "xss-stored")
        self.assertEqual(stable["packet_sha256"], packet["packet_sha256"])
        # attribution: payload author recorded against the packet hash
        path = self.root / "packet.json"
        path.write_text(json.dumps(packet))
        result = self.led.record_payload(path, "deepseek-v4.1-flash", provider="deepseek",
                                         note="designed from packet")
        self.assertEqual(result["model"], "deepseek-v4.1-flash")
        self.assertEqual(result["packet_sha256"], packet["packet_sha256"])
        rows = self.led.db.execute("SELECT * FROM payload_events").fetchall()
        self.assertEqual(len(rows), 1)
        with self.assertRaises(ValueError):
            self.led.record_payload(path, "  ")   # attribution is mandatory
        with self.assertRaises(ValueError):
            self.led.packet(self.aid, "nosuchfield", "xss-stored")


class BlindBundleTests(FieldFixture):
    def bundle(self, executed=True, evidence=b"<script>var m='MARKER'</script>",
               control=b"<p>clean</p>", callback_url="", attempt="b" * 20):
        epath = self.root / "ev" / "surface.html"
        epath.parent.mkdir(exist_ok=True)
        epath.write_bytes(evidence.replace(b"MARKER", b"11111111payloadmarker"
                                          if executed else b"untouched"))
        cpath = self.root / "ev" / "control.html"
        cpath.write_bytes(control)
        return {"schema_version": 1, "asset_id": self.aid, "attempt_id": attempt,
                "payload_marker": "11111111payloadmarker",
                "started_at": "2026-01-01T00:00:00+00:00",
                "ended_at": "2026-01-01T01:00:00+00:00",
                "surface": "staff-inbox", "evidence":
                    {"path": "ev/surface.html",
                     "sha256": hashlib.sha256(epath.read_bytes()).hexdigest()},
                "control": {"path": "ev/control.html",
                            "sha256": hashlib.sha256(cpath.read_bytes()).hexdigest()},
                "callback_url": callback_url, "note": "operator capture"}

    def test_executed_bundle_correlates(self):
        result = self.led.blind(self.aid, self.bundle())
        self.assertEqual(result["assessment"], "executed-surface-correlated")
        self.assertTrue(result["executed_marker_found"])
        self.assertFalse(result["finding_promoted"])
        self.assertFalse(result["executed"])
        self.assertIn("validator", result["basis"])
        row = self.led.db.execute(
            "SELECT * FROM canary_events WHERE surface='blind-exec:staff-inbox'").fetchone()
        self.assertIsNotNone(row)

    def test_not_executed_or_inconclusive(self):
        result = self.led.blind(self.aid, self.bundle(executed=False))
        self.assertEqual(result["assessment"], "not-executed-or-inconclusive")

    def test_bundle_validation_rules(self):
        good = self.bundle()
        with self.assertRaises(ValueError):  # evidence == control
            same = self.bundle(evidence=b"<p>same</p>", control=b"<p>same</p>")
            self.led.blind(self.aid, same)
        with self.assertRaises(ValueError):  # unordered window
            bad_time = self.bundle()
            bad_time["started_at"], bad_time["ended_at"] = bad_time["ended_at"], \
                bad_time["started_at"]
            self.led.blind(self.aid, bad_time)
        with self.assertRaises(ValueError):  # window > 24h
            late = self.bundle()
            late["ended_at"] = "2026-01-03T00:00:00+00:00"
            self.led.blind(self.aid, late)
        with self.assertRaises(ValueError):  # short attempt marker
            self.led.blind(self.aid, self.bundle(attempt="short"))
        with self.assertRaises(ValueError):  # foreign asset id
            foreign = self.bundle()
            foreign["asset_id"] = self.aid + 1
            self.led.blind(self.aid, foreign)

    def test_callback_host_grants(self):
        with self.assertRaises(ValueError) as caught:
            self.led.blind(self.aid, self.bundle(
                callback_url=f"https://oast.example/{'b' * 20}"))
        self.assertIn("xss.callback_hosts", str(caught.exception))
        self.ctx.campaign.raw.setdefault("xss", {})["callback_hosts"] = ["oast.example"]
        result = self.led.blind(self.aid, self.bundle(
            callback_url=f"https://oast.example/{'b' * 20}"))
        self.assertEqual(result["assessment"], "executed-surface-correlated")


class ScoreClassTests(FieldFixture):
    def test_html_injection_and_ssti_seeding(self):
        classes = applicable_classes({"value": "https://acme.test/profile",
                                      "attrs": {"params": ["bio", "description"]}})
        self.assertIn("html-injection", classes)
        self.assertIn("bio", classes["html-injection"])
        classes = applicable_classes({"value": "https://acme.test/render",
                                      "attrs": {"params": ["tpl", "theme"]}})
        self.assertIn("ssti", classes)
        self.assertNotIn("html-injection", applicable_classes(
            {"value": "https://acme.test/api/users", "attrs": {"params": ["page"]}}))


if __name__ == "__main__":
    unittest.main()
