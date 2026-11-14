"""Offline SSRF workflow boundaries plus a deliberately bounded owned-loopback lab."""
import contextlib
import copy
import hashlib
import http.client
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, quote, urlsplit

from recon.campaign import OutOfScope
from recon.cli import main
from recon.pipeline import Recon
from recon.report import write_reports
from recon.score import applicable_classes, ssrf_parameters
from recon.skillmap import skill_path, skills_for
from recon.ssrf import CASES, SSRFWorkflow, context_value, read_json
from tests.test_recon import write_campaign


def sha(data):
    return hashlib.sha256(data).hexdigest()


def context(url="https://app.example.test/api/import"):
    return {"request_url": url, "method": "GET", "account": "A", "role": "member",
            "tenant": "test-a", "workflow": "draft-preview", "field": "json.sourceUrl"}


class SSRFFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "campaign"
        self.camp = write_campaign(self.root, "active", [], in_scope=["app.example.test"])
        self.camp.raw["ssrf"] = {"callback_hosts": ["*.callbacks.example.test", "receiver.example.test"]}
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.aid = self.ctx.add_endpoint("https://app.example.test/api/import", "har", method="GET",
                                         params=["sourceUrl"])
        self.fx = SSRFWorkflow(self.ctx)
        self.context = context()

    def artifact(self, name, data):
        if isinstance(data, str):
            data = data.encode()
        dest = self.root / ".recon" / "captures" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return {"path": dest.relative_to(self.root).as_posix(), "sha256": sha(data)}

    def pair(self):
        return [self.artifact("replay", "response data")["path"],
                self.artifact("control", "control data")["path"]]

    def card(self, plan, name):
        return next(c for c in plan["cases"] if c["id"] == name)

    def bundle(self):
        token = "bv_attempt_0123456789abcdef"
        host = token + ".callbacks.example.test"
        callback = "https://" + host + "/probe"
        event = {"id": "event-1", "attempt_id": token, "timestamp": "2026-11-12T12:00:02Z",
                 "hostname": host, "protocol": "https", "origin": "application",
                 "artifact": self.artifact("event", "GET /probe HTTP/1.1\r\nHost: " + host)}
        return {"schema_version": 1, "asset_id": self.aid, "context": self.context.copy(),
                "request_url": self.context["request_url"], "attempt_id": token,
                "started_at": "2026-11-12T12:00:00Z", "ended_at": "2026-11-12T12:01:00Z",
                "callback_url": callback, "request": self.artifact("request", "GET /api/import?url=" + callback),
                "response": self.artifact("response", "HTTP/1.1 200 OK\r\n\r\nbv_response_9876543210abcdef"),
                "control": self.artifact("control", "HTTP/1.1 400 Bad Request\r\n\r\nblocked"),
                "response_canary": "bv_response_9876543210abcdef", "events": [event]}


class SSRFPlanTests(SSRFFixture):
    def test_29_cases_are_unique_offline_and_never_confirm(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
                patch("subprocess.run", side_effect=AssertionError("subprocess forbidden")):
            plan = self.fx.plan(self.aid, self.context)
        self.assertEqual(len(CASES), 29)
        self.assertEqual(len({r[0] for r in CASES}), 29)
        self.assertEqual(plan["unresolved_cases"], 29)
        self.assertFalse(plan["finding_promoted"])
        self.assertIn("manual", plan["gate_basis"])
        self.assertIn("not enforced", plan["budget_basis"])
        self.assertEqual(plan["blockers"], [])
        self.assertEqual(self.ctx.store.request_count(), 0)

    def test_blank_context_is_blocked_and_record_requires_exact_fields(self):
        plan = self.fx.plan(self.aid)
        self.assertIn("exact", " ".join(plan["blockers"]))
        for bad in (None, {}, {**self.context, "extra": "value"}, {**self.context, "tenant": ""},
                    {**self.context, "role": "member\nadmin"}, {**self.context, "method": "TRACE"}):
            with self.subTest(context=bad), self.assertRaises(ValueError):
                self.fx.record(self.aid, bad, "baseline", "blocked", "not ready")
        self.assertEqual(context_value({**self.context, "method": "get"})["method"], "GET")

    def test_exact_url_must_match_scope_and_family(self):
        for url, error in (("https://app.example.test/other", ValueError),
                           ("https://outside.example.test/api/import", OutOfScope)):
            with self.subTest(url=url), self.assertRaises(error):
                self.fx.plan(self.aid, {**self.context, "request_url": url})

    def test_passive_exclusion_and_missing_method_grant_block_plan(self):
        self.camp.policy.mode = "passive"
        self.camp.raw["excluded_bug_classes"] = ["ssrf"]
        plan = self.fx.plan(self.aid, {**self.context, "method": "POST"})
        self.assertEqual(len(plan["blockers"]), 3)
        self.assertIn("passive", plan["blockers"][0])
        self.assertIn("excluded", plan["blockers"][1])
        self.assertIn("method", plan["blockers"][2])
        # Historical assertions can still be retained; recording is not execution approval.
        result = self.fx.record(self.aid, self.context, "baseline", "blocked", "SSRF excluded")
        self.assertFalse(result["executed"])

    def test_all_seven_methods_are_individually_recognized(self):
        for method in ("GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"):
            self.camp.policy.allowed_methods = ["GET", method] if method != "GET" else ["GET"]
            self.assertFalse(self.fx.plan(self.aid, {**self.context, "method": method})["blockers"])
        self.camp.policy.allowed_methods = ["GET"]
        self.assertIn("method", self.fx.plan(self.aid, {**self.context, "method": "DELETE"})["blockers"][0])

    def test_bad_config_or_effort_caps_fail_closed(self):
        for cfg in ([], {"per_case_effort_cap": 0}, {"per_case_effort_cap": 11}, {"per_case_effort_cap": True}):
            self.camp.raw["ssrf"] = cfg
            with self.subTest(cfg=cfg), self.assertRaises(ValueError):
                self.fx.plan(self.aid, self.context)

    def test_depth_grants_unlock_branches_and_all_grants_everything(self):
        plan = self.fx.plan(self.aid, self.context)
        card = self.card(plan, "credential-use")
        self.assertEqual(card["authorization"], "grant-required")
        self.assertIn("add credential", card["gate"])
        self.assertEqual(plan["depth_grants"], [])
        self.assertEqual(self.card(plan, "baseline")["authorization"], "standard")
        self.camp.raw["ssrf"]["depth_grants"] = ["credential"]
        card = self.card(self.fx.plan(self.aid, self.context), "credential-use")
        self.assertEqual(card["authorization"], "granted")
        self.assertIn("granted by campaign ssrf.depth_grants", card["gate"])
        self.assertEqual(self.card(self.fx.plan(self.aid, self.context),
                                   "internal-canary")["authorization"], "grant-required")
        self.camp.raw["ssrf"]["depth_grants"] = ["all"]
        plan = self.fx.plan(self.aid, self.context)
        self.assertEqual(plan["depth_grants"], sorted(
            {"dns", "internal", "cloud", "credential", "protocol", "execution"}))
        self.assertFalse(any(c["authorization"] == "grant-required" for c in plan["cases"]))
        self.assertEqual(self.card(plan, "baseline")["authorization"], "standard")

    def test_invalid_depth_grants_fail_closed(self):
        for grants in (["nonsense"], ["base"], ["internal", "internal"], "all", [1], ["validation"]):
            self.camp.raw["ssrf"]["depth_grants"] = grants
            with self.subTest(grants=grants), self.assertRaises(ValueError):
                self.fx.plan(self.aid, self.context)

    def test_scope_template_documents_depth_grants(self):
        from recon.campaign import scope_template
        template = scope_template("lab", ["example.com"], "passive")
        self.assertEqual(template["ssrf"]["depth_grants"], [])
        self.assertIn('"all"', template["ssrf"]["_depth_grants_help"])
        self.assertIn("callback_hosts", template["ssrf"])

    def test_non_endpoint_inferred_and_out_of_scope_assets_are_refused(self):
        service = self.ctx.add("service", "https://app.example.test", source="html")
        inferred = self.ctx.add_endpoint("https://app.example.test/api/guessed", "version-sibling")
        for aid in (service, inferred, True, -1):
            with self.subTest(aid=aid), self.assertRaises(ValueError):
                self.fx.plan(aid, self.context)
        self.camp.scope = type(self.camp.scope).from_lists(["elsewhere.example.test"], [])
        self.ctx.scope = self.camp.scope
        with self.assertRaises(OutOfScope):
            self.fx.plan(self.aid)

    def test_trigger_fields_surfaces_and_coverage_skill(self):
        fields = ["sourceUrl", "json.integration.callbackUrl", "items[0][image_url]", "feedURI", "q", "userId"]
        self.assertEqual(ssrf_parameters(fields), sorted(fields[:4]))
        for path in ("/api/import", "/proxy", "/webhooks/test", "/feeds/refresh", "/oembed"):
            self.assertIn("ssrf", applicable_classes({"value": "https://app.example.test" + path, "attrs": {}}))
        self.assertNotIn("ssrf", applicable_classes({"value": "https://app.example.test/api/user", "attrs": {}}))
        self.assertEqual(skills_for("ssrf"), ("hunt-ssrf",))
        self.assertTrue(skill_path("hunt-ssrf").is_file())
        self.ctx.refresh_coverage()
        coverage = next(p for p in write_reports(self.ctx) if p.name == "coverage.md").read_text()
        self.assertTrue(any("| ssrf |" in l and "hunt-ssrf" in l for l in coverage.splitlines()))


class SSRFLedgerTests(SSRFFixture):
    def test_distinct_artifacts_required_for_observed_and_negative(self):
        pair = self.pair()
        for state in ("observed", "negative"):
            for artifacts, count in (([], 1), ([pair[0], pair[0]], 1), (pair, 0)):
                with self.subTest(state=state, count=count), self.assertRaises(ValueError):
                    self.fx.record(self.aid, self.context, "fetch-control", state, "comparison", artifacts, count)
        event = self.fx.record(self.aid, self.context, "fetch-control", "observed", "review needed", pair, 2)
        self.assertEqual(len(event["artifacts"]), 2)
        self.assertFalse(event["finding_promoted"])
        for ref in event["artifacts"]:
            path = self.root / ref["path"]
            self.assertEqual(sha(path.read_bytes()), ref["sha256"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.ctx.store.network_attempts(), 0)

    def test_each_context_and_exact_url_variant_is_separate(self):
        self.fx.record(self.aid, self.context, "baseline", "blocked", "A only")
        for field, value in (("account", "B"), ("role", "admin"), ("tenant", "test-b"),
                             ("workflow", "saved-worker"), ("field", "json.otherUrl"),
                             ("method", "HEAD"), ("request_url", self.context["request_url"] + "?mode=stored")):
            with self.subTest(field=field):
                card = self.card(self.fx.plan(self.aid, {**self.context, field: value}), "baseline")
                self.assertEqual(card["state"], "untested")

    def test_stale_scope_and_asset_snapshots_preserve_rows(self):
        self.fx.record(self.aid, self.context, "baseline", "blocked", "retained")
        self.camp.raw["rules"] = ["changed approval"]
        plan = self.fx.plan(self.aid, self.context)
        self.assertEqual(plan["stale_events_retained"], 1)
        self.assertEqual(self.card(plan, "baseline")["state"], "untested")
        self.fx.record(self.aid, self.context, "baseline", "inconclusive", "new scope")
        self.ctx.store.update_attrs(self.aid, {"params": ["anotherUrl"]})
        self.assertEqual(self.fx.plan(self.aid, self.context)["stale_events_retained"], 2)
        self.assertEqual(self.ctx.store.db.execute("SELECT count(*) FROM ssrf_case_events").fetchone()[0], 2)

    def test_effort_cap_is_per_case_not_global_completeness(self):
        for i in range(3):
            self.fx.record(self.aid, self.context, "parser-encoding", "inconclusive", "attempt " + str(i),
                           requests_declared=1)
        plan = self.fx.plan(self.aid, self.context)
        self.assertTrue(self.card(plan, "parser-encoding")["effort_exhausted"])
        self.assertFalse(self.card(plan, "redirect-hop")["effort_exhausted"])
        self.assertEqual(plan["unresolved_cases"], 29)
        self.assertEqual(plan["external_requests_declared"], 3)

    def test_modified_and_missing_stored_evidence_is_unresolved(self):
        event = self.fx.record(self.aid, self.context, "response-read", "observed", "review", self.pair(), 2)
        before = self.fx.plan(self.aid, self.context)
        self.assertEqual(self.card(before, "response-read")["artifact_integrity"], "hashes-match")
        dest = self.root / event["artifacts"][0]["path"]
        dest.write_text("tampered")
        after = self.fx.plan(self.aid, self.context)
        self.assertEqual(self.card(after, "response-read")["artifact_integrity"], "missing-or-modified")
        self.assertEqual(after["unresolved_cases"], 29)
        dest.unlink()
        self.assertEqual(self.card(self.fx.plan(self.aid, self.context), "response-read")["artifact_integrity"],
                         "missing-or-modified")

    def test_parent_paths_and_symlink_escapes_are_refused(self):
        outside = self.root.parent / "outside.txt"
        outside.write_text("private")
        link = self.root / "linked.txt"
        link.symlink_to(outside)
        for path in ("../outside.txt", str(outside), "linked.txt", ".recon"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.fx.record(self.aid, self.context, "baseline", "blocked", "not usable", [path])

    def test_symlinked_evidence_store_and_corrupt_existing_hash_are_refused(self):
        pair = self.pair()
        store = self.root / ".recon/ssrf-evidence"
        outside = self.root.parent / "external-evidence"
        outside.mkdir()
        store.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.fx.record(self.aid, self.context, "baseline", "blocked", "no", pair)
        store.unlink()
        event = self.fx.record(self.aid, self.context, "baseline", "blocked", "retained", pair)
        (self.root / event["artifacts"][0]["path"]).write_text("corrupt")
        with self.assertRaises(ValueError):
            self.fx.record(self.aid, self.context, "baseline", "blocked", "no overwrite", pair)

    def test_relative_campaign_root_can_reuse_existing_evidence(self):
        # Match a CLI campaign supplied as a relative path; no process-wide chdir needed.
        import os
        from recon.campaign import Campaign
        pair = self.pair()
        relative = Path(os.path.relpath(self.root))
        ctx = Recon(Campaign.load(relative), log=lambda _: None)
        try:
            workflow = SSRFWorkflow(ctx)
            for _ in range(2):
                result = workflow.record(self.aid, self.context, "baseline", "blocked", "same evidence", pair)
                self.assertEqual(len(result["artifacts"]), 2)
        finally:
            ctx.store.close()

    def test_validation_and_size_bounds(self):
        for case_id, state, note, count in (("missing", "blocked", "note", 0), ("baseline", "confirmed", "note", 0),
                                            ("baseline", "blocked", "", 0), ("baseline", "blocked", "note", -1),
                                            ("baseline", "blocked", "note", True)):
            with self.subTest(case=case_id, state=state), self.assertRaises(ValueError):
                self.fx.record(self.aid, self.context, case_id, state, note, requests_declared=count)
        with self.assertRaises(ValueError):
            self.fx.record(self.aid, self.context, "baseline", "blocked", "note", ["x"] * 9)
        large = self.artifact("large", b"x" * 5_000_001)["path"]
        with self.assertRaises(ValueError):
            self.fx.record(self.aid, self.context, "baseline", "blocked", "note", [large])


class SSRFCorrelationTests(SSRFFixture):
    def test_correlates_http_and_separate_canary_without_promotion_or_traffic(self):
        bundle = self.bundle()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = self.fx.correlate(self.aid, bundle)
        self.assertEqual(result["assessment"], "http-interaction-correlated")
        self.assertTrue(result["response_canary_observed"])
        self.assertFalse(result["finding_promoted"])
        self.assertIn("operator-supplied", " ".join(result["warnings"]))
        self.assertEqual(self.ctx.store.request_count(), 0)

    def test_dns_unknown_no_event_and_silence_remain_narrow(self):
        for origin, protocol, expected in (("unknown", "https", "unattributed-interaction"),
                                           ("application", "dns", "dns-interaction-correlated")):
            bundle = self.bundle()
            bundle["events"][0].update(origin=origin, protocol=protocol)
            result = self.fx.correlate(self.aid, bundle)
            self.assertEqual(result["assessment"], expected)
            self.assertFalse(result["response_canary_observed"])
        bundle["events"] = []
        result = self.fx.correlate(self.aid, bundle)
        self.assertEqual(result["assessment"], "no-correlated-interaction")
        self.assertIn("inconclusive", " ".join(result["warnings"]))

    def test_event_dedup_time_host_attempt_origin_and_protocol_filters(self):
        bundle = self.bundle()
        good = bundle["events"][0]
        bundle["events"].append(copy.deepcopy(good))
        for i, change in enumerate(({"origin": "browser"}, {"origin": "analyst"}, {"origin": "scanner"},
                                     {"timestamp": "2026-11-12T12:03:00Z"}, {"hostname": "wrong.example.test"},
                                     {"attempt_id": "another-attempt-1234"}, {"protocol": "smtp"})):
            bundle["events"].append({**good, "id": "ignored-" + str(i), **change})
        result = self.fx.correlate(self.aid, bundle)
        self.assertEqual(result["matched_event_ids"], ["event-1"])
        self.assertEqual(sum(result["ignored"].values()), 8)
        bundle["events"][1]["origin"] = "unknown"
        with self.assertRaisesRegex(ValueError, "conflicting duplicate"):
            self.fx.correlate(self.aid, bundle)

    def test_marker_only_in_normalized_event_cannot_manufacture_correlation(self):
        bundle = self.bundle()
        bundle["events"][0]["artifact"] = self.artifact("event-no-marker", "unrelated raw log")
        result = self.fx.correlate(self.aid, bundle)
        self.assertFalse(result["matched_event_ids"])
        self.assertFalse(result["response_canary_observed"])

    def test_reflection_or_control_presence_is_not_readback(self):
        for location in ("request", "control"):
            bundle = self.bundle()
            ref = bundle[location]
            original = (self.root / ref["path"]).read_bytes()
            bundle[location] = self.artifact(location, original + bundle["response_canary"].encode())
            self.assertFalse(self.fx.correlate(self.aid, bundle)["response_canary_observed"])
        bundle = self.bundle()
        bundle["response_canary"] = bundle["attempt_id"]
        bundle["response"] = self.artifact("response-reflection", bundle["callback_url"])
        self.assertFalse(self.fx.correlate(self.aid, bundle)["response_canary_observed"])

    def test_context_version_extra_fields_and_identity_are_strict(self):
        for change in ({"schema_version": True}, {"asset_id": self.aid + 1}, {"extra": "no"},
                       {"context": None}, {"context": {**self.context, "request_url": "https://app.example.test/other"}},
                       {"request_url": self.context["request_url"] + "?changed=1"}):
            bundle = self.bundle()
            bundle.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.fx.correlate(self.aid, bundle)

    def test_callback_grants_boundaries_and_url_validation(self):
        bundle = self.bundle()
        for hosts in ([], ["*"], "*.callbacks.example.test", ["callbacks.example.test"],
                      ["*.example.test.attacker.invalid"], ["https://callbacks.example.test"]):
            self.camp.raw["ssrf"]["callback_hosts"] = hosts
            with self.subTest(hosts=hosts), self.assertRaises(ValueError):
                self.fx.correlate(self.aid, bundle)
        self.camp.raw["ssrf"]["callback_hosts"] = ["*.callbacks.example.test"]
        for callback in ("file:///tmp/data", "https://user:pass@receiver.example.test/probe", "https://bad host/probe",
                         "https://receiver.example.test:99999/probe", "https://receiver.example.test/probe#fragment"):
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                self.fx.correlate(self.aid, {**bundle, "callback_url": callback})

    def test_time_canary_marker_and_event_bounds(self):
        for change in ({"started_at": "2026-11-12T12:00:00"}, {"ended_at": "2026-11-12T12:11:00Z"},
                       {"ended_at": "2026-11-12T11:59:59Z"}, {"attempt_id": "short"},
                       {"response_canary": "tiny"}, {"response_canary": "x" * 1025}, {"events": [{}] * 2001}):
            bundle = self.bundle()
            bundle.update(change)
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                self.fx.correlate(self.aid, bundle)

    def test_hash_path_distinct_control_and_request_binding_checks(self):
        bundle = self.bundle()
        for key in ("request", "response", "control"):
            changed = copy.deepcopy(bundle)
            changed[key]["sha256"] = "0" * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.fx.correlate(self.aid, changed)
        for change in ({"control": bundle["response"]},
                       {"request": self.artifact("bad-request", "no callback here")},
                       {"response": {"path": "../outside", "sha256": "0" * 64}}):
            with self.subTest(change=list(change)), self.assertRaises(ValueError):
                self.fx.correlate(self.aid, {**bundle, **change})

    def test_empty_canary_is_allowed_without_readback_claim(self):
        bundle = self.bundle()
        bundle["response_canary"] = ""
        self.assertFalse(self.fx.correlate(self.aid, bundle)["response_canary_observed"])

    def test_aggregate_artifact_size_is_bounded(self):
        bundle = self.bundle()
        event = bundle["events"][0]
        prefix = (bundle["attempt_id"] + " " + event["hostname"]).encode()
        bundle["events"] = [{**event, "id": "large-" + str(i),
                             "artifact": self.artifact("large-" + str(i), prefix + bytes([65 + i]) * 4_999_000)}
                            for i in range(6)]
        with self.assertRaisesRegex(ValueError, "25 megabytes"):
            self.fx.correlate(self.aid, bundle)


class SSRFSkillPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = skill_path("hunt-ssrf").parent
        self.text = skill_path("hunt-ssrf").read_text()
        self.refs = "\n".join(p.read_text() for p in (self.directory / "references").glob("*.md"))

    def test_every_card_is_explained_and_references_are_local(self):
        import re
        self.assertLess(len(self.text.splitlines()), 500)
        for case_id, _, _ in CASES:
            self.assertIn("`" + case_id + "`", self.text + self.refs)
        for relative in re.findall(r"\]\((references/[^)]+)\)", self.text):
            self.assertTrue((self.directory / relative).is_file())

    def test_execution_evidence_budget_and_reportability_limits_are_explicit(self):
        for needle in ("dedicated visible browser", "8080", "9876/mcp", "blocked", "depth_grants",
                       "chain_next", "impact ladder", "owned lab", "operator-owned",
                       "negative control", "per-case effort cap", "All four no",
                       "not integrated", "not a verified origin", "manually", "hypothetical"):
            self.assertIn(needle.lower(), (self.text + self.refs).lower())
        for needle in ("AWS", "IMDSv2", "Metadata-Flavor: Google", "Metadata: true", "X-Forwarded-For"):
            self.assertIn(needle, self.text + self.refs)
        hunter = (Path(__file__).resolve().parents[1] / "recon/prompts/hunter.md").read_text()
        self.assertIn("instead of the generic send/coverage shortcuts", hunter)
        self.assertIn("credential access is not RCE", hunter)

    def test_sources_are_pinned_and_unverified_claims_not_imported(self):
        sources = (self.directory / "references/sources.md").read_text()
        for needle in ("9d61d9142c350c1f6188ffb3c5e6e34407cf8438",
                       "0accf5fdc71ec7f03273aebb99268a8609f8dfd4", "CC BY-NC 4.0", "MIT",
                       "XSS", "placeholders", "inconsistent", "not independently"):
            self.assertIn(needle, sources)
        self.assertNotIn("execution_successful", self.text)
        self.assertNotIn("gopher://", self.text + self.refs)


class SSRFChainTests(SSRFFixture):
    def record_observed(self, case_id):
        return self.fx.record(self.aid, self.context, case_id, "observed",
                              "chain edge proven", self.pair(), 2)

    def test_observed_cloud_case_unlocks_credential_use_and_ranks_it_next(self):
        self.record_observed("aws-imds")
        plan = self.fx.plan(self.aid, self.context)
        card = self.card(plan, "credential-use")
        self.assertEqual(card["prerequisites_satisfied_by"], ["aws-imds"])
        self.assertTrue(card["chain_ready"])
        self.assertEqual(plan["chain_next"][0], "credential-use")

    def test_chain_edges_accumulate_and_negative_does_not_satisfy(self):
        self.record_observed("fetch-control")
        self.fx.record(self.aid, self.context, "gcp-metadata", "negative",
                       "header refused", self.pair(), 2)
        plan = self.fx.plan(self.aid, self.context)
        self.assertEqual(self.card(plan, "parser-authority")["prerequisites_satisfied_by"],
                         ["fetch-control"])
        self.assertEqual(self.card(plan, "credential-use")["prerequisites_satisfied_by"], [])
        self.assertFalse(self.card(plan, "credential-use")["chain_ready"])

    def test_chain_next_excludes_resolved_cases(self):
        self.fx.record(self.aid, self.context, "baseline", "not-applicable", "no fetch surface")
        plan = self.fx.plan(self.aid, self.context)
        self.assertNotIn("baseline", plan["chain_next"])
        self.assertIn("fetch-control", plan["chain_next"])


class SSRFCLITests(SSRFFixture):
    def invoke(self, action, *args):
        # CLI reloads the campaign; persist the optional offline matching configuration.
        (self.root / "scope.json").write_text(json.dumps(self.camp.raw))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                patch("socket.socket", side_effect=AssertionError("CLI must remain offline")):
            rc = main(["ssrf", action, str(self.root), "--asset-id", str(self.aid), *args])
        return rc, out.getvalue(), err.getvalue()

    def test_plan_record_status_correlate_commands_are_offline(self):
        path = self.root / "context.json"
        path.write_text(json.dumps(self.context))
        rc, text, _ = self.invoke("plan", "--context", str(path))
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(text)["cases"]), 29)
        rc, text, _ = self.invoke("record", "--context", str(path), "--case", "baseline", "--state", "blocked",
                                  "--note", "no connected browser")
        self.assertEqual(rc, 0)
        self.assertFalse(json.loads(text)["executed"])
        rc, text, _ = self.invoke("status", "--context", str(path))
        self.assertEqual(self.card(json.loads(text), "baseline")["state"], "blocked")
        bundle = self.root / "bundle.json"
        bundle.write_text(json.dumps(self.bundle()))
        rc, text, _ = self.invoke("correlate", "--bundle", str(bundle))
        self.assertEqual(rc, 0)
        self.assertFalse(json.loads(text)["finding_promoted"])

    def test_invalid_json_or_context_exits_without_network(self):
        path = self.root / "bad.json"
        path.write_text("{")
        self.assertEqual(self.invoke("plan", "--context", str(path))[0], 1)
        path.write_text("{}")
        self.assertEqual(self.invoke("plan", "--context", str(path))[0], 1)
        path.write_bytes(b" " * 1_000_001)
        with self.assertRaises(ValueError):
            read_json(path)


def lab_get(url):
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1":
        raise AssertionError("owned loopback only")
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=2)
    try:
        conn.request("GET", parts.path + ("?" + parts.query if parts.query else ""))
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read(4096)
    finally:
        conn.close()


class SSRFOwnedLoopbackTests(unittest.TestCase):
    def test_bounded_vulnerable_and_fixed_fetchers_with_readback_control(self):
        token = "bv_lab_attempt_1234567890abcdef"
        canary = b"bv_private_response_abcdef1234567890"
        hits = []
        receiver_url = ""  # filled before either server accepts a request

        class Receiver(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(canary if self.path == "/private/" + token else b"public-control")

            def log_message(self, *args):
                pass

        class Fetcher(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parts = urlsplit(self.path)
                destination = parse_qs(parts.query).get("url", [""])[0]
                # Never an open proxy: this test fixture can fetch just two exact owned URLs.
                allowed = (receiver_url + "/public/" + token, receiver_url + "/private/" + token)
                if destination not in allowed or parts.path not in ("/vulnerable", "/fixed"):
                    self.send_error(400)
                    return
                if parts.path == "/fixed" and destination != allowed[0]:
                    self.send_error(403)
                    return
                _, _, body = lab_get(destination)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with contextlib.ExitStack() as stack:
            servers = []
            for handler in (Receiver, Fetcher):
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
                stack.callback(server.server_close)
                servers.append(server)
            receiver_url = "http://127.0.0.1:" + str(servers[0].server_address[1])
            entry_url = "http://127.0.0.1:" + str(servers[1].server_address[1])
            for server in servers:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                stack.callback(thread.join, 2)
                stack.callback(server.shutdown)
            private = receiver_url + "/private/" + token
            public = receiver_url + "/public/" + token
            bad_request = entry_url + "/vulnerable?url=" + quote(private, safe="")
            self.assertNotIn(canary, bad_request.encode())
            status, _, result = lab_get(bad_request)
            self.assertEqual((status, result), (200, canary))
            status, _, fixed = lab_get(entry_url + "/fixed?url=" + quote(private, safe=""))
            self.assertEqual(status, 403)
            self.assertNotIn(canary, fixed)
            status, _, control = lab_get(entry_url + "/fixed?url=" + quote(public, safe=""))
            self.assertEqual((status, control), (200, b"public-control"))
            self.assertEqual(hits, ["/private/" + token, "/public/" + token])
            status, _, _ = lab_get(entry_url + "/vulnerable?url=" + quote("http://elsewhere.invalid/", safe=""))
            self.assertEqual(status, 400)
        # This proves only this two-destination fixture, not arbitrary parsers, clouds or browsers.


if __name__ == "__main__":
    unittest.main()
