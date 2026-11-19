"""Offline takeover integration and fail-closed evidence regressions."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon.campaign import Campaign, ConfigError
from recon.cli import main
from recon.pipeline import Recon
from recon.report import write_reports
from recon.skillmap import skills_for
from recon.takeover import TakeoverLedger, read_json
from tests.test_recon import write_campaign


class TakeoverLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [], in_scope=["acme.test", "*.acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.ledger = TakeoverLedger(self.ctx)

    def capture(self, name="old.acme.test"):
        def obs(host, typ, value="", result="answer"):
            return {"name": host, "record_type": typ, "value": value, "result": result,
                    "resolver": "owned-fixture", "observed_at": "2026-11-15T12:00:00Z",
                    "vantage": "recursive"}
        return {"schema": 1, "source": "owned-fixture",
                "observations": [obs(name, "CNAME", "unclaimed.herokuapp.com"),
                                 obs("unclaimed.herokuapp.com", "A", result="nxdomain"),
                                 obs("unclaimed.herokuapp.com", "AAAA", result="nxdomain")]}

    def candidate(self):
        self.ledger.import_capture(self.capture())
        return self.ledger.plan()["candidates"][0]["id"]

    def artifact(self, name, text):
        path = self.root / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return str(path.relative_to(self.root))

    def event(self, cid, stage="precheck", **overrides):
        data = {"schema": 1, "candidate": cid, "stage": stage, "state": "observed",
                "note": "Owned fixture only, no live provider verification", "channel": "owned-lab",
                "artifacts": {"review": self.artifact("review", "trust preconditions reviewed")}}
        return {**data, **overrides}

    def test_import_deduplicates_and_does_not_enqueue_or_send(self):
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            first = self.ledger.import_capture(self.capture())
            again = self.ledger.import_capture(self.capture())
        self.assertEqual(first["input_id"], again["input_id"])
        self.assertEqual(self.ctx.store.jobs(), [])
        self.assertEqual(self.ctx.store.request_count(), 0)
        self.assertEqual(self.ctx.store.db.execute("SELECT count(*) FROM to_dns").fetchone()[0], 3)
        self.assertFalse(again["inventory_complete"])
        self.assertEqual(skills_for("subdomain-takeover"), ("hunt-takeover",))
        self.assertTrue(any(c["bug_class"] == "subdomain-takeover" for c in self.ctx.store.coverage()))

    def test_scope_excluded_names_stay_intel_no_candidate_or_job(self):
        self.ledger.import_capture(self.capture("outside.example"))
        self.assertEqual(self.ledger.plan()["total"], 0)
        self.assertIn("outside.example", self.ledger.status()["out_of_scope"])
        self.assertEqual(self.ctx.store.jobs(), [])

    def test_trusted_host_ranks_above_isolated_host_and_edges_are_conditional(self):
        self.ledger.import_capture(self.capture("isolated.acme.test"))
        self.ctx.store.record_request("GET", "https://app.acme.test/", 200, "fixture", [],
                                      {"content-security-policy": "script-src https://old.acme.test",
                                       "set-cookie": "test=secret-value; Domain=acme.test; Secure; HttpOnly"},
                                      b'<script src="https://old.acme.test/app.js"></script>',
                                      body_complete=True, basis="owned-fixture")
        cid = self.candidate()
        plan = self.ledger.plan()
        self.assertEqual(plan["candidates"][0]["name"], "old.acme.test")
        self.assertTrue(all(e["conditional"] for e in self.ledger.show(cid)["trust_edges"]))
        self.assertNotIn("secret-value", json.dumps(plan))
        self.assertTrue(self.ledger.show(cid)["lifecycle"])
        self.assertIn("source_sha256", plan["candidates"][0]["trust_edges"][0])

    def test_response_body_and_metadata_tampering_detected(self):
        rid = self.ctx.store.record_request("GET", "https://app.acme.test/", 200, "fixture", [], {},
                                            b'"https://old.acme.test/"', body_complete=True)
        self.candidate()
        response = self.ctx.store.response(rid)
        (self.ctx.store.bodies_dir / response["body_sha256"]).write_bytes(b"tampered")
        self.assertFalse(self.ledger.verify()["ok"])

    def test_response_header_snapshot_changes_are_detected(self):
        rid = self.ctx.store.record_request("GET", "https://app.acme.test/", 200, "fixture", [],
                                            {"content-security-policy": "script-src https://old.acme.test"}, b"ok")
        self.candidate()
        self.ctx.store.db.execute("UPDATE requests SET resp_headers='{}' WHERE id=?", (rid,))
        self.ctx.store.db.commit()
        self.assertFalse(self.ledger.verify()["ok"])

    def test_archived_reference_is_preserved_but_not_current_trust(self):
        rid = self.ctx.store.record_request("GET", "https://web.archive.org/web/20220101000000id_/https://app.acme.test/old.js",
                                            200, "wayback-js", [], {"content-security-policy": "script-src https://old.acme.test"},
                                            b'fetch("https://old.acme.test/api")', body_complete=True, basis="archive")
        self.ctx.store.upsert_asset("js", "https://app.acme.test/old.js", host="app.acme.test",
                                    attrs={"archive_request_id": rid, "archive_last": "20220101000000"})
        cid = self.candidate()
        edges = self.ledger.show(cid)["trust_edges"]
        self.assertTrue(edges)
        self.assertTrue(all(e["details"]["historical"] for e in edges))
        self.assertNotIn("csp-script", {e["kind"] for e in edges})
        self.assertEqual(self.ctx.store.jobs(), [])

    def test_ct_certificate_dates_remain_source_labelled_history(self):
        from recon.sources import job_crtsh
        from types import SimpleNamespace
        aid, _ = self.ctx.store.upsert_asset("domain", "acme.test", host="acme.test")
        raw = [{"name_value": "old.acme.test", "not_before": "2022-01-01T00:00:00",
                "not_after": "2022-04-01T00:00:00"}]
        with patch.object(self.ctx.passive, "get", return_value=SimpleNamespace(
                status=200, body=json.dumps(raw).encode(), request_id=42)):
            job_crtsh(self.ctx, {"id": aid, "value": "acme.test"})
        host = self.ctx.store.find_asset("host", "old.acme.test")
        self.assertEqual(host["attrs"]["ct_certificates"][0]["response_ref"], 42)
        self.assertEqual(host["attrs"]["ct_certificates"][0]["not_after"], "2022-04-01T00:00:00")
        self.ledger.sync()
        self.assertEqual(self.ledger.plan()["total"], 0)

    def test_dns_mail_dependencies_reverse_map_to_host_without_claiming_mail(self):
        data = self.capture()
        anchor = data["observations"][0]
        data["observations"].append({**anchor, "name": "acme.test", "record_type": "TXT",
                                     "value": "v=spf1 include:old.acme.test -all"})
        self.ledger.import_capture(data)
        candidate = next(c for c in self.ledger.plan()["candidates"] if c["name"] == "old.acme.test")
        edge = next(e for e in candidate["trust_edges"] if e["kind"] == "spf-include")
        self.assertEqual(edge["source_kind"], "input")
        self.assertTrue(edge["conditional"])
        self.assertIn("claimability-not-established", " ".join(edge["details"]["gaps"]))

    def test_hsts_without_includesubdomains_is_not_attached_to_sibling(self):
        self.ctx.store.record_request("GET", "https://acme.test/", 200, "fixture", [],
                                      {"strict-transport-security": "max-age=1000"}, b"ok", body_complete=True)
        cid = self.candidate()
        self.assertNotIn("hsts", {e["kind"] for e in self.ledger.show(cid)["trust_edges"]})

    def test_normal_addresses_and_soa_do_not_seed_takeover_claimability(self):
        sample = self.capture()["observations"][0]
        data = {"schema": 1, "source": "owned inventory", "observations": [
            {**sample, "record_type": "A", "value": "192.0.2.1"},
            {**sample, "record_type": "SOA", "value": "ns.acme.test hostmaster.acme.test 1 60 60 60 60"}]}
        self.ledger.import_capture(data)
        self.assertEqual(self.ledger.plan()["total"], 0)
        self.assertEqual(self.ctx.store.coverage(), [])

    def test_campaign_observation_cap_rejects_before_partial_import(self):
        sample = self.capture()["observations"][0]
        def bundle(prefix, count):
            return {"schema": 1, "source": "bounded owned inventory", "observations": [
                {**sample, "name": f"{prefix}{n}.acme.test", "record_type": "A", "value": "192.0.2.1"}
                for n in range(count)]}
        self.ledger.import_capture(bundle("a", 1001))
        with self.assertRaisesRegex(ValueError, "2000 unique"):
            self.ledger.import_capture(bundle("b", 1000))
        self.assertEqual(self.ctx.store.db.execute("SELECT count(*) FROM to_inputs").fetchone()[0], 1)

    def test_input_and_artifact_tampering_detected(self):
        cid = self.candidate()
        result = self.ledger.record(self.event(cid))
        row = self.ctx.store.db.execute("SELECT data FROM to_events WHERE id=?", (result["event_id"],)).fetchone()
        artifact = json.loads(row[0])["artifacts"]["review"]
        (self.root / artifact["path"]).write_text("altered")
        self.assertFalse(self.ledger.verify()["ok"])
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.ledger.record(self.event(cid))

    def test_precheck_is_required_and_stale_events_do_not_unlock_claims(self):
        cid = self.candidate()
        roles = {k: self.artifact(k, k + " own fixture") for k in ("provider", "namespace", "control")}
        with self.assertRaisesRegex(ValueError, "precheck"):
            self.ledger.record(self.event(cid, "claimable", artifacts=roles))
        self.ledger.record(self.event(cid))
        self.ctx.campaign.raw["rules"] = ["new reviewed rules"]
        self.assertTrue(self.ledger.show(cid)["events"][0]["stale"])
        with self.assertRaisesRegex(ValueError, "precheck"):
            self.ledger.record(self.event(cid, "claimable", artifacts=roles))

    def test_live_grants_budget_and_approval_fail_closed(self):
        cid = self.candidate()
        event = self.event(cid, channel="burp", requests=1)
        with self.assertRaisesRegex(ValueError, "reviewed rules"):
            self.ledger.record(event)
        self.ctx.campaign.raw.update({"program_url": "https://program.example/rules", "rules": ["owned claim only"],
                                      "takeover": {"rules_reviewed": "2026-11-15", "budget": 1}})
        with self.assertRaisesRegex(ValueError, "grant"):
            self.ledger.record(event)
        self.ctx.campaign.raw["takeover"]["grants"] = ["claim"]
        self.ledger.record(event)
        with self.assertRaisesRegex(ValueError, "budget"):
            self.ledger.record(event)

    def test_fresh_provider_and_negative_wildcards_allow_only_evidence_recording(self):
        from recon.store import now
        data = self.capture()
        for observation in data["observations"]:
            observation["observed_at"] = now()
        for label in ("bvcontrol1a", "bvcontrol2b"):
            data["observations"].append({**data["observations"][0], "name": label + ".acme.test",
                "value": "", "result": "nxdomain", "vantage": "wildcard-control", "control_for": "old.acme.test"})
        self.ctx.campaign.raw.update({"program_url": "https://program.example/rules", "rules": ["fixture grant, not executed"],
            "takeover": {"rules_reviewed": now()[:10], "budget": 4, "grants": ["claim"], "providers": [
                {"provider": "heroku", "status": "vulnerable", "source": "https://source.example/fixture",
                 "checked": now()[:10]}]}})
        self.ledger.import_capture(data)
        cid = next(c["id"] for c in self.ledger.plan()["candidates"] if c["name"] == "old.acme.test")
        self.ledger.record(self.event(cid, channel="burp", requests=1))
        roles = {k: self.artifact(k, k + " supplied fixture") for k in ("provider", "namespace", "control")}
        with patch("socket.socket", side_effect=AssertionError("recording is offline")):
            recorded = self.ledger.record(self.event(cid, "claimable", channel="burp", requests=1, artifacts=roles))
        self.assertFalse(recorded["executed"])
        self.assertEqual(self.ctx.store.network_attempts(), 0)
        from recon.takeover_dns import provider_info
        actual_provider_info = provider_info
        def expired_provider(*args, **kwargs):
            return {**actual_provider_info(*args, **kwargs), "stale": True, "age_days": 91}
        with patch("recon.takeover_dns.provider_info", side_effect=expired_provider):
            shown = self.ledger.show(cid)
            self.assertTrue(shown["events"][-1]["stale"])
            self.assertFalse(self.ledger._current_event(cid, "claimable"))
        self.ctx.campaign.raw["takeover"]["providers"][0]["status"] = "patched"
        self.ledger.record(self.event(cid, channel="burp", requests=1))
        with self.assertRaisesRegex(ValueError, "stale, patched or unknown"):
            self.ledger.record(self.event(cid, "claimable", channel="burp", requests=1, artifacts=roles))

    def test_blocked_event_can_be_preserved_without_live_permission(self):
        cid = self.candidate()
        result = self.ledger.record(self.event(cid, stage="claim", state="blocked", channel="burp", artifacts={}))
        self.assertFalse(result["finding_promoted"])
        self.assertEqual(self.ledger.show(cid)["stages"][2]["state"], "blocked")

    def test_paths_and_event_schema_are_bounded(self):
        cid = self.candidate()
        with self.assertRaisesRegex(ValueError, "inside"):
            self.ledger.record(self.event(cid, artifacts={"review": "../outside"}))
        with self.assertRaisesRegex(ValueError, "schema"):
            self.ledger.record(self.event(cid, unexpected="bad"))
        with self.assertRaises(ValueError):
            self.ledger.plan(0)
        path = self.root / "oversized.json"
        path.write_bytes(b" " * 2_000_001)
        with self.assertRaisesRegex(ValueError, "two megabytes"):
            read_json(path)

    def test_reports_cli_and_no_automatic_finding(self):
        cid = self.candidate()
        write_reports(self.ctx)
        self.assertIn("Takeover candidates (conditional", (self.root / "recon.md").read_text())
        self.assertIn("hunt-takeover", (self.root / "coverage.md").read_text())
        for args in (["takeover", "show", str(self.root), "--candidate", str(cid)],
                     ["takeover", "status", str(self.root)], ["takeover", "verify", str(self.root)]):
            with contextlib.redirect_stdout(io.StringIO()), patch("socket.socket", side_effect=AssertionError("offline")):
                self.assertEqual(main(args), 0)
        tables = {r[0] for r in self.ctx.store.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "findings" in tables:
            self.assertEqual(self.ctx.store.db.execute("SELECT count(*) FROM findings").fetchone()[0], 0)

    def test_cli_import_and_sync_use_only_operator_capture(self):
        path = self.root / "capture.json"
        path.write_text(json.dumps(self.capture()))
        for args in (["takeover", "import", str(self.root), str(path)],
                     ["takeover", "sync", str(self.root)], ["takeover", "plan", str(self.root)]):
            with contextlib.redirect_stdout(io.StringIO()), patch("socket.getaddrinfo", side_effect=AssertionError("no DNS")):
                self.assertEqual(main(args), 0)
        self.assertEqual(self.ctx.store.jobs(), [])

    def test_invalid_takeover_config_is_not_ignored(self):
        path = self.root / "scope.json"
        raw = json.loads(path.read_text())
        for value in ({"grants": ["automatic-claim"]}, {"budget": True}, {"executor": True}):
            raw["takeover"] = value
            path.write_text(json.dumps(raw))
            with self.assertRaises(ConfigError):
                Campaign.load(self.root)

    def test_live_receipts_validate_entire_url_not_only_hostname(self):
        from recon.takeover import capture_receipt
        for url in ("ftp://old.acme.test/", "https://user:pass@old.acme.test/", "https://old.acme.test/logout"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                capture_receipt(json.dumps({"request_url": url, "status": 200, "body": "owned marker"}).encode(), self.ctx.scope)
        with self.assertRaisesRegex(ValueError, "full request_url"):
            capture_receipt(json.dumps({"host": "old.acme.test", "status": 200, "body": "owned marker"}).encode(), self.ctx.scope)


if __name__ == "__main__":
    unittest.main()
