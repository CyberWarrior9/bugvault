"""Offline access-control/mass-assignment workflow and owned-loopback proof pairing."""
import contextlib
import http.server
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.authz import AuthzLedger
from recon.campaign import Campaign, ConfigError, scope_template, validate_authz
from recon.cli import main
from recon.fields import FieldLedger, module_of
from recon.pipeline import Recon
from recon.report import write_reports
from recon.score import applicable_classes
from recon.skillmap import skills_for

MARKER = "owned_marker_12345678"


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "campaign"
        self.root.mkdir()
        cfg = scope_template("owned-lab", [], "active", ["POST", "PATCH", "DELETE"])
        cfg["in_scope"] = ["lab.test"]
        cfg["authz"] = {"probe_grants": ["method-matrix", "sibling-expand",
                                         "representation-fuzz", "read-extraction", "write-proof"],
                        "chain_grants": ["token-use", "lateral"],
                        "probe_budget": {"requests": 40, "per_host": 20}}
        self.cfg = cfg
        self.save()
        self.ctx = Recon(Campaign.load(self.root), log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.ledger = AuthzLedger(self.ctx)
        self.seq = 0

    def save(self):
        (self.root / "scope.json").write_text(json.dumps(self.cfg))

    def endpoint(self, path="/api/v2/admin/report", method="GET", fields=(),
                 extra=None):
        return self.ctx.add_endpoint(f"https://lab.test{path}", "har", method=method,
                                     params=fields, extra=extra)

    def capture(self, aid, method="GET", account="a", role="user", tenant="a",
                workflow="list", body=(), representation="application/json",
                auth="cookie", operations=(), path=None, query=()):
        self.seq += 1
        self.ctx.store.add_observation(
            aid, method, account, {"query": list(query), "body": list(body), "header": [],
                                   "cookie": [], "ids": {}}, 200, "har",
            capture_key=f"capture:{self.seq}",
            context={"role": role, "tenant": tenant, "workflow_state": workflow,
                     **({"path": path} if path else {}),
                     "csrf_meta": {"content_type": representation, "auth": auth,
                                   "graphql_operations": list(operations)}})

    def context(self, method="GET", path="/api/v2/admin/report", role="user"):
        cards = self.ledger.plan(limit=100)["targets"]
        return next(c["context_id"] for t in cards if t["method"] == method and
                    t["url"].endswith(path) for c in t["contexts"] if c["role"] == role)

    def artifact(self, name, text):
        path = self.root / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return "evidence/" + name

    def triple(self, suffix="", sensitive=False, marker=MARKER):
        redacted = " [redacted]" if sensitive else ""
        return [f"baseline={self.artifact('base'+suffix, marker+' authorized'+redacted)}",
                f"test={self.artifact('test'+suffix, marker+' unauthorized'+redacted)}",
                f"control={self.artifact('ctrl'+suffix, 'wrong resource denied')}" ]


class AuthzTests(Fixture):
    def test_delete_seeding_and_dual_ownership(self):
        self.assertIn("mass-assignment", applicable_classes({
            "value": "https://lab.test/delete", "attrs": {"methods": ["DELETE"]}}))
        self.assertNotIn("mass-assignment", applicable_classes({
            "value": "https://lab.test/api/items", "attrs": {"methods": ["GET"]}}))
        aid = self.endpoint("/api/internal/item/{id}")
        self.ctx.store.update_attrs(aid, {"id_params": ["id"]})
        classes = applicable_classes(self.ctx.store.get_asset(aid))
        self.assertIn("access-control", classes)
        self.assertIn("idor-bola", classes)
        self.assertEqual(skills_for("access-control"), ("hunt-access-control",))
        self.assertEqual(skills_for("mass-assignment"), ("hunt-access-control",))

    def test_idempotent_sync_exact_context_and_stale(self):
        aid = self.endpoint()
        self.capture(aid, role="user", tenant="a")
        self.capture(aid, account="b", role="admin", tenant="a")
        self.assertEqual(self.ledger.sync()["contexts_added"], 2)
        self.assertEqual(self.ledger.sync()["contexts_added"], 0)
        cid = self.context()
        result = self.ledger.record(cid, "ac-role", "observed", marker=MARKER,
                                    artifacts=self.triple("role", True), impact="admin",
                                    proof_basis="test accounts A/B on owned marker",
                                    requests=3, note="Low role returned owned admin marker")
        self.assertFalse(result["executed"])
        self.assertFalse(result["finding_promoted"])
        self.assertTrue(self.ledger.verify()["verified"])
        self.capture(aid, body=("filter",), role="user", tenant="a")
        self.assertEqual(self.ledger._event_state(self.ledger._context(cid)[0], "ac-role", "default")[0],
                         "observed")  # before sync, new capture is not yet reconciled
        self.ledger.sync()
        self.assertEqual(self.ledger._event_state(self.ledger._context(cid)[0], "ac-role", "default")[0],
                         "stale")
        self.assertFalse(self.ledger.verify()["verified"])
        self.assertTrue(self.ledger.verify()["artifact_integrity"])

    def test_grants_budget_missing_proof_and_tamper(self):
        aid = self.endpoint()
        self.capture(aid)
        self.capture(aid, account="b", role="admin", tenant="a")
        cid = self.context()
        self.cfg["authz"]["probe_grants"].remove("sibling-expand")
        self.save()
        self.ctx.campaign.raw = self.cfg
        self.ledger.grants = validate_authz(self.cfg["authz"])
        with self.assertRaisesRegex(ValueError, "grant"):
            self.ledger.record(cid, "ac-version", "attempted", variant="expand:v1", requests=1)
        with self.assertRaisesRegex(ValueError, "baseline"):
            self.ledger.record(cid, "ac-role", "observed", marker=MARKER,
                               requests=3, proof_basis="owned marker")
        with self.assertRaisesRegex(ValueError, "budget"):
            self.ledger.record(cid, "ac-role", "attempted", marker=MARKER, requests=21)
        result = self.ledger.record(cid, "ac-role", "observed", marker=MARKER,
                                    requests=3, proof_basis="owned marker",
                                    artifacts=self.triple("tamper"))
        self.assertTrue(result["event_id"])
        row = self.ledger.db.execute("SELECT path FROM authz_artifacts WHERE event_id=? LIMIT 1",
                                     (result["event_id"],)).fetchone()
        (self.root / row["path"]).write_text("tampered")
        self.assertFalse(self.ledger.verify()["verified"])
        self.assertFalse(self.ledger.verify()["artifact_integrity"])
        self.assertIn("stale", self.ledger.status()["totals"])

    def test_deleted_evidence_role_cannot_keep_an_observed_case(self):
        aid = self.endpoint()
        self.capture(aid)
        self.capture(aid, role="admin", account="b")
        cid = self.context()
        event = self.ledger.record(cid, "ac-role", "observed", marker=MARKER,
                                   requests=3, proof_basis="owned controlled result",
                                   artifacts=self.triple("deleted-role"))
        self.ledger.db.execute("DELETE FROM authz_artifacts WHERE event_id=? AND role='control'",
                               (event["event_id"],))
        self.ledger.db.commit()
        self.assertEqual(self.ledger._event_state(self.ledger._context(cid)[0],
                                                  "ac-role", "default")[0], "stale")
        self.assertFalse(self.ledger.verify()["verified"])
        self.assertIn("proof roles missing", str(self.ledger.verify()["invalid"]))

    def test_negative_write_needs_owned_before_after_and_untyped_post_stays_gated(self):
        aid = self.endpoint("/api/v2/update", "POST", ("role",))
        self.capture(aid, method="POST", body=("role",))
        cid = self.context(method="POST", path="/api/v2/update")
        with self.assertRaisesRegex(ValueError, "before/after"):
            self.ledger.record(cid, "ma-privileged-field", "negative", grant="write-proof",
                               marker=MARKER, requests=3, proof_basis="ignored in owned readback",
                               artifacts=self.triple("negative-no-readback"))
        self.cfg["authz"]["probe_grants"].remove("write-proof")
        self.ctx.campaign.raw = self.cfg
        self.ledger.grants = validate_authz(self.cfg["authz"])
        with self.assertRaisesRegex(ValueError, "write-proof"):
            self.ledger.record(cid, "ac-projection", "observed", marker=MARKER,
                               requests=3, proof_basis="unknown POST behavior",
                               artifacts=self.triple("post"))

    def test_declared_mime_contexts_do_not_disappear_after_one_capture(self):
        aid = self.endpoint("/api/v2/format", "POST", extra={
            "spec_content_types": ["application/json", "application/xml"]})
        before = next(t for t in self.ledger.plan()["targets"] if t["asset_id"] == aid)
        self.assertEqual({c["representation"] for c in before["contexts"]},
                         {"application/json", "application/xml"})
        self.capture(aid, method="POST", body=("label",), representation="application/json")
        after = next(t for t in self.ledger.plan()["targets"] if t["asset_id"] == aid)
        self.assertTrue(any(c["basis"] == "captured" for c in after["contexts"]))
        self.assertTrue(any(c["representation"] == "application/xml" and not c["superseded"]
                            for c in after["contexts"]))

    def test_family_path_and_query_shapes_are_never_cross_assigned(self):
        paths = ("/api/admin/items/101", "/api/admin/items/102")
        aid = self.endpoint(paths[0] + "?filter=a", "GET")
        self.endpoint(paths[0] + "?sort=title", "GET")
        self.endpoint(paths[1] + "?filter=b", "GET")
        self.capture(aid, path=paths[0], query=("filter",))
        self.capture(aid, path=paths[1], query=("filter",), account="b")
        cards = [t for t in self.ledger.plan(limit=100)["targets"] if t["asset_id"] == aid]
        self.assertEqual(len(cards), 3)
        actual = {t["url"]: t for t in cards}
        self.assertEqual(sum(t["basis"] == "captured" for t in cards), 2)
        self.assertEqual(len(actual[f"https://lab.test{paths[0]}?filter="]["contexts"]), 1)
        self.assertEqual(actual[f"https://lab.test{paths[0]}?sort="]["basis"], "declared")
        self.assertEqual(actual[f"https://lab.test{paths[1]}?filter="]["contexts"][0]["account"], "b")
        self.assertEqual(self.ledger.sync()["contexts_added"], 0)

    def test_field_diff_keeps_concrete_paths_and_auth_mechanisms_separate(self):
        path1, path2 = "/api/v2/items/101", "/api/v2/items/102"
        aid = self.endpoint(path1, "POST")
        self.endpoint(path2, "PATCH")
        self.capture(aid, method="POST", path=path1, body=("role",))
        self.capture(aid, method="PATCH", path=path2, body=("admin",))
        self.capture(aid, method="POST", path=path1, body=("token",), auth="bearer")
        data = FieldLedger(self.ctx).diff(module_of(self.ctx.store.get_asset(aid)["value"]))
        self.assertEqual(len(data["groups"]), 3)
        self.assertTrue(all(not g["comparable"] for g in data["groups"]))
        self.assertNotIn(path1, json.dumps(data))
        self.assertNotIn(path2, json.dumps(data))

    def test_field_diff_does_not_merge_graphql_operation_selectors(self):
        aid = self.endpoint("/graphql", "POST")
        self.capture(aid, method="POST", operations=("query Viewer",), body=("public",))
        self.capture(aid, method="POST", operations=("mutation Admin",), body=("privileged",))
        data = FieldLedger(self.ctx).diff(module_of(self.ctx.store.get_asset(aid)["value"]))
        self.assertEqual(len(data["groups"]), 2)
        self.assertEqual({g["context"]["selector"] for g in data["groups"]},
                         {"query Viewer", "mutation Admin"})
        self.assertTrue(all(not g["comparable"] for g in data["groups"]))

    def test_delete_candidate_requires_assignable_field_and_readback(self):
        aid = self.endpoint("/api/v2/items/remove", "DELETE")
        self.capture(aid, method="DELETE", body=())
        cid = self.context(method="DELETE", path="/api/v2/items/remove")
        card = next(x for t in self.ledger.plan()["targets"] for c in t["contexts"]
                    if c["context_id"] == cid for x in c["cases"] if x["case"] == "ma-privileged-field")
        self.assertEqual(card["readiness"], "waiting-prerequisite")
        with self.assertRaisesRegex(ValueError, "n-a needs"):
            self.ledger.record(cid, "ma-privileged-field", "n-a", note="No body seen")
        self.capture(aid, method="DELETE", body=("soft_delete",))
        self.assertEqual(self.ledger._readiness(*self.ledger._context(cid), "ma-privileged-field")[0],
                         "waiting-prerequisite")  # until sync
        self.ledger.sync()
        with self.assertRaisesRegex(ValueError, "before/after"):
            self.ledger.record(cid, "ma-privileged-field", "observed", grant="write-proof",
                               marker=MARKER, requests=3, proof_basis="owned soft-delete state",
                               artifacts=self.triple("delete"))
        artifacts = self.triple("del2") + [
            f"before={self.artifact('before-del', MARKER+' active')}",
            f"after={self.artifact('after-del', 'soft_deleted=true')}" ]
        self.assertEqual(self.ledger.record(cid, "ma-privileged-field", "observed",
                                            grant="write-proof", marker=MARKER, requests=3,
                                            proof_basis="owned soft-delete readback",
                                            artifacts=artifacts)["state"], "observed")

    def test_chain_parent_and_secret_redaction(self):
        aid = self.endpoint()
        self.capture(aid)
        self.capture(aid, account="b", role="admin", tenant="a")
        cid = self.context()
        with self.assertRaisesRegex(ValueError, "unredacted"):
            self.ledger.record(cid, "ac-role", "observed", marker=MARKER, requests=3,
                               impact="secret", proof_basis="owned marker",
                               artifacts=self.triple("raw") + [
                                   f"trace={self.artifact('secret', 'Bearer abcdefghijklmnopqrstuvwxyz')}"])
        with self.assertRaisesRegex(ValueError, "parent"):
            self.ledger.record(cid, "token-use", "observed", grant="token-use",
                               marker=MARKER, requests=3, proof_basis="owned token",
                               artifacts=self.triple("chain"))
        parent = self.ledger.record(cid, "ac-role", "observed", marker=MARKER, requests=3,
                                    impact="secret", proof_basis="owned synthetic token",
                                    artifacts=self.triple("parent", True))["event_id"]
        child_marker = "owned_marker_87654321"
        child = self.ledger.record(cid, "token-use", "observed", grant="token-use",
                                   parent_id=parent, marker=child_marker, requests=3,
                                   impact="secret", proof_basis="owned token exercise",
                                   artifacts=self.triple("child", True, marker=child_marker))
        self.assertTrue(child["event_id"])
        self.assertFalse(child["executed"])

    def test_native_reference_must_exist_and_coarse_conflict_report(self):
        aid = self.endpoint()
        self.capture(aid)
        cid = self.context()
        with self.assertRaisesRegex(ValueError, "native request ID"):
            self.ledger.record(cid, "ac-role", "blocked", note="waiting browser",
                               tool_refs=["native:999"])
        self.ctx.refresh_coverage()
        self.ctx.store.set_coverage(aid, "access-control", "tested", "one case attempted")
        self.assertIn([aid, "access-control", "tested"], self.ledger.status()["coarse_conflicts"])
        content = next(p for p in write_reports(self.ctx) if p.name == "coverage.md").read_text()
        self.assertIn("Access-control and mass-assignment cases", content)

    def test_negative_is_a_variant_outcome_not_class_completion(self):
        aid = self.endpoint("/api/v2/report")
        self.capture(aid)
        cid = self.context(path="/api/v2/report")
        self.ledger.record(cid, "ac-unauth", "negative", marker=MARKER, requests=3,
                           proof_basis="owned marker absent without auth",
                           artifacts=self.triple("negative"))
        self.ctx.refresh_coverage()
        self.ctx.store.set_coverage(aid, "access-control", "tested", "one variant only")
        status = self.ledger.status()
        self.assertEqual(status["totals"]["negative"], 1)
        self.assertTrue(any(row[2] == "ac-unauth" and "variant-negative" in row[3]
                            for row in status["open"]))
        self.assertIn([aid, "access-control", "tested"], status["coarse_conflicts"])

    def test_impact_first_cards_are_not_id_order(self):
        self.endpoint("/api/v2/items")
        important = self.endpoint("/api/v2/admin/export")
        plan = self.ledger.plan(limit=1)
        self.assertEqual(plan["targets"][0]["asset_id"], important)
        self.assertGreater(plan["truncated_targets"], 0)

    def test_attempt_then_write_proof_reuses_receipt_without_new_traffic(self):
        aid = self.endpoint("/api/v2/profile", "POST", ("role",))
        self.capture(aid, method="POST", body=("role",))
        cid = self.context(method="POST", path="/api/v2/profile")
        self.ledger.record(cid, "ma-privileged-field", "attempted", grant="write-proof",
                           marker=MARKER, requests=3)
        artifacts = self.triple("transition") + [
            f"before={self.artifact('transition-before', MARKER+' role=user')}",
            f"after={self.artifact('transition-after', MARKER+' role=admin [redacted]')}" ]
        result = self.ledger.record(cid, "ma-privileged-field", "observed", grant="write-proof",
                                    marker=MARKER, requests=0, impact="admin",
                                    proof_basis="owned test profile readback", artifacts=artifacts)
        self.assertEqual(result["requests_declared"], 0)
        with self.assertRaisesRegex(ValueError, "one write attempt"):
            self.ledger.record(cid, "ma-privileged-field", "attempted", grant="write-proof",
                               marker=MARKER, requests=1)
        self.assertEqual(self.ledger.status()["totals"]["observed"], 1)

    def test_stale_attempt_cannot_be_turned_into_zero_request_proof(self):
        aid = self.endpoint("/api/v2/profile", "POST", ("role",))
        self.capture(aid, method="POST", body=("role",))
        cid = self.context(method="POST", path="/api/v2/profile")
        self.ledger.record(cid, "ma-privileged-field", "attempted", grant="write-proof",
                           marker=MARKER, requests=1)
        self.capture(aid, method="POST", body=("role", "privilege"))
        self.ledger.sync()
        with self.assertRaisesRegex(ValueError, "stale or superseded"):
            self.ledger.record(cid, "ma-privileged-field", "observed", grant="write-proof",
                               marker=MARKER, requests=0, proof_basis="owned result",
                               artifacts=self.triple("stale") + [
                                   f"before={self.artifact('stale-before', MARKER+' user')}",
                                   f"after={self.artifact('stale-after', MARKER+' admin')}" ])

    def test_blocked_chain_without_grant_is_reportable_as_blocked(self):
        aid = self.endpoint()
        self.capture(aid)
        cid = self.context()
        self.cfg["authz"]["chain_grants"] = []
        self.ctx.campaign.raw = self.cfg
        self.ledger.grants = validate_authz(self.cfg["authz"])
        event = self.ledger.record(cid, "token-use", "blocked", note="no written grant")
        self.assertEqual(event["state"], "blocked")
        self.assertEqual(self.ledger.status()["chain_rungs"][0]["case_id"], "token-use")

    def test_context_safe_role_tenant_and_grant_variant_limits(self):
        aid = self.endpoint()
        self.capture(aid, role="user", tenant="a")
        self.capture(aid, account="b", role="admin", tenant="b")
        self.capture(aid, account="c", role="user", tenant="b")
        cid = self.context()
        c, t = self.ledger._context(cid)
        self.assertEqual(self.ledger._readiness(c, t, "ac-role")[0], "waiting-prerequisite")
        self.assertEqual(self.ledger._readiness(c, t, "ac-tenant")[0], "ready")
        with self.assertRaisesRegex(ValueError, "another case"):
            self.ledger.record(cid, "ac-role", "attempted", variant="fuzz:body",
                               grant="representation-fuzz", requests=1)
        with self.assertRaisesRegex(ValueError, "two labelled"):
            self.ledger.record(cid, "ac-role", "observed", marker=MARKER,
                               requests=3, proof_basis="owned marker", artifacts=self.triple("mismatch"))
        self.assertEqual(self.ledger.record(cid, "ac-version", "blocked",
                                            note="no old version in scope")["state"], "blocked")

    def test_method_matrix_requires_effective_method_grant(self):
        aid = self.endpoint()
        self.capture(aid)
        cid = self.context()
        with self.assertRaisesRegex(ValueError, "effective HTTP method"):
            self.ledger.record(cid, "ac-method", "attempted", variant="matrix:override",
                               grant="method-matrix", marker=MARKER, requests=1)
        with self.assertRaisesRegex(ValueError, "effective HTTP method"):
            self.ledger.record(cid, "ac-method", "attempted", variant="matrix:PUT:header",
                               grant="method-matrix", marker=MARKER, requests=1)
        self.assertEqual(self.ledger.record(cid, "ac-method", "attempted",
                                            variant="matrix:PATCH:header", grant="method-matrix",
                                            marker=MARKER, requests=1)["state"], "attempted")

    def test_readonly_cap_and_root_cause_group(self):
        aid = self.endpoint()
        self.capture(aid)
        cid = self.context()
        self.cfg["authz"]["probe_budget"]["readonly_variants"] = 1
        self.ctx.campaign.raw = self.cfg
        self.ledger.grants = validate_authz(self.cfg["authz"])
        self.ledger.record(cid, "ac-unauth", "attempted", variant="default", requests=1,
                           marker=MARKER,
                           root_key="missing-auth-check", related_cases=["ac-version"])
        with self.assertRaisesRegex(ValueError, "variant cap"):
            self.ledger.record(cid, "ac-unauth", "attempted", variant="extract:debug",
                               grant="read-extraction", marker="owned_another_987654321", requests=1)
        self.assertEqual(self.ledger.status()["root_groups"][0]["root_key"],
                         "missing-auth-check")

    def test_graphql_selectors_and_unknown_contexts_not_pooled(self):
        aid = self.endpoint("/graphql", "POST", fields=("query",))
        self.capture(aid, method="POST", operations=("query Viewer",), body=("query",))
        self.capture(aid, method="POST", operations=("mutation UpdateOwn",), body=("query",))
        cards = [t for t in self.ledger.plan()["targets"] if t["asset_id"] == aid]
        self.assertEqual({t["selector"] for t in cards}, {"", "query Viewer", "mutation UpdateOwn"})
        self.assertEqual(len([t for t in cards if t["selector"] == "query Viewer"][0]["contexts"]), 1)
        self.assertIn("idor-bola", applicable_classes(self.ctx.store.get_asset(aid)))

    def test_multi_operation_graphql_capture_does_not_certify_individual_query(self):
        aid = self.endpoint("/graphql", "POST", fields=("query",))
        self.capture(aid, method="POST", operations=("query Viewer", "mutation Change"),
                     body=("query",))
        cards = [t for t in self.ledger.plan()["targets"] if t["asset_id"] == aid]
        self.assertEqual(next(t for t in cards if t["selector"] == "query Viewer")["basis"],
                         "declared")
        self.assertEqual(next(t for t in cards if t["selector"] == "mutation Change")["basis"],
                         "declared")
        self.assertEqual(next(t for t in cards if t["selector"] == "")["basis"], "captured")
        self.assertEqual(next(c for t in cards if t["selector"] == "query Viewer"
                              for x in t["contexts"] for c in x["cases"]
                              if c["case"] == "ac-projection")["readiness"], "waiting-capture")

    def test_value_free_diff_context_isolation_and_method_matched_spec(self):
        aid = self.endpoint("/api/v2/items", "POST", ("title",))
        self.endpoint("/api/v2/items", "PATCH", ("title", "privilege"))
        self.ctx.store.update_attrs(aid, {"spec_fields": [
            {"method": "POST", "location": "body", "name": "title"},
            {"method": "PATCH", "location": "body", "name": "title"}]})
        self.capture(aid, method="POST", body=("title",))
        self.capture(aid, method="PATCH", body=("title", "privilege"))
        self.capture(aid, method="PATCH", account="b", tenant="b", body=("title", "secret_only_b"))
        data = FieldLedger(self.ctx).diff(module_of(self.ctx.store.get_asset(aid)["value"]))
        known = [g for g in data["groups"] if g["context"]["account"] == "a"]
        self.assertEqual(len(known), 1)
        self.assertTrue(known[0]["comparable"])
        patch = next(o for o in known[0]["operations"] if o["method"] == "PATCH")
        self.assertEqual(patch["sent_not_declared"]["body"], ["privilege"])
        self.assertNotIn("secret_only_b", json.dumps(known))
        self.assertIn("not server-accepted", data["basis"])
        self.assertFalse(data["executed"])

    def test_cli_end_to_end_and_offline_only(self):
        aid = self.endpoint()
        self.capture(aid)
        for args in (("authz", "sync"), ("authz", "plan"), ("authz", "status"),
                     ("authz", "verify"), ("fields", "diff")):
            with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()) as output:
                extra = ["--module", module_of(self.ctx.store.get_asset(aid)["value"])] \
                    if args == ("fields", "diff") else []
                self.assertEqual(main([*args, str(self.root), *extra]), 0)
                self.assertFalse(json.loads(output.getvalue())["executed"])
        cid = self.context()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["authz", "record", str(self.root), "--context", str(cid),
                                   "--case", "ac-unauth", "--state", "blocked",
                                   "--note", "No connected browser"]), 0)
            self.assertEqual(json.loads(output.getvalue())["state"], "blocked")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["authz", "verify", str(self.root)]), 0)
            self.assertEqual(json.loads(output.getvalue())["events_checked"], 1)
        self.assertEqual(self.ctx.store.request_count(), 0)


class ConfigTests(unittest.TestCase):
    def test_grants_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cfg = scope_template("lab", [], "active")
            cfg["in_scope"] = ["lab.test"]
            for bad in ({"probe_grants": ["all"], "probe_budget": {"requests": 2, "per_host": 1}},
                        {"probe_grants": ["write-proof"]},
                        {"chain_grants": ["lateral", "lateral"],
                         "probe_budget": {"requests": 3, "per_host": 1}},
                        {"probe_grants": [], "probe_budget": {"requests": True, "per_host": 1}},
                        {"unknown": "yes"}, {"_hidden_grant": "yes"}, None):
                cfg["authz"] = bad
                (root / "scope.json").write_text(json.dumps(cfg))
                with self.subTest(bad=bad), self.assertRaises(ConfigError):
                    Campaign.load(root)


class OwnedLoopbackTests(unittest.TestCase):
    def test_mass_assignment_applied_vs_ignored_on_owned_loopback_records(self):
        profiles = {"v1": "user", "v2": "user"}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                version = "v1" if "/v1/" in self.path else "v2"
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                if version == "v1":
                    profiles[version] = body.get("privilege", profiles[version])
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def do_GET(self):
                version = "v1" if "/v1/" in self.path else "v2"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"marker": MARKER, "role": profiles[version]}).encode())

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_address[1]}"

            def request(version, method="GET", payload=None):
                url = f"{origin}/api/{version}/profile"
                data = json.dumps(payload).encode() if payload is not None else None
                with urlopen(Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"}), timeout=2) as r:
                    return r.read().decode()

            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / "owned"
                root.mkdir()
                cfg = scope_template("owned-loopback", [], "active", ["POST"])
                cfg["in_scope"] = [origin]
                cfg["authz"] = {"probe_grants": ["write-proof"], "chain_grants": [],
                                "probe_budget": {"requests": 10, "per_host": 10}}
                (root / "scope.json").write_text(json.dumps(cfg))
                ctx = Recon(Campaign.load(root), log=lambda _: None)
                try:
                    ledger = AuthzLedger(ctx)
                    evidence = root / "evidence"
                    evidence.mkdir()
                    for version, expected in (("v1", "admin"), ("v2", "user")):
                        before = request(version)
                        self.assertIn('"role": "user"', before)
                        response = request(version, "POST", {"privilege": "admin", "marker": MARKER})
                        after = request(version)
                        self.assertEqual(json.loads(after)["role"], expected)
                        aid = ctx.add_endpoint(f"{origin}/api/{version}/profile", "har",
                                               method="POST", params=["privilege", "marker"])
                        ctx.store.add_observation(
                            aid, "POST", "test-a", {"query": [],
                                                     "body": ["privilege", "marker"]}, 200, "owned-lab",
                            capture_key="profile:" + version,
                            context={"role": "user", "tenant": "test", "workflow_state": "profile",
                                     "csrf_meta": {"content_type": "application/json", "auth": "header"}})
                        target = next(t for t in ledger.plan()["targets"] if t["asset_id"] == aid and
                                      t["method"] == "POST")
                        cid = target["contexts"][0]["context_id"]
                        files = {"baseline": f"{MARKER} authorized owned profile [redacted]",
                                 "test": f"{MARKER} write response {response} [redacted]",
                                 "control": "other test account denied",
                                 "before": before + " [redacted]", "after": after + " [redacted]"}
                        refs = []
                        for role, text in files.items():
                            (evidence / f"{version}-{role}.txt").write_text(text)
                            refs.append(f"{role}=evidence/{version}-{role}.txt")
                        state = "observed" if version == "v1" else "negative"
                        result = ledger.record(cid, "ma-privileged-field", state,
                                               grant="write-proof", marker=MARKER,
                                               proof_basis="owned profile before/after lab readback",
                                               impact="admin" if state == "observed" else "none",
                                               artifacts=refs, requests=3)
                        self.assertEqual(result["state"], state)
                    self.assertTrue(ledger.verify()["verified"])
                    self.assertEqual(ctx.store.request_count(), 0)
                finally:
                    ctx.store.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_guarded_and_unguarded_function_control_without_external_target(self):
        marker = MARKER

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                role = self.headers.get("X-Lab-Role")
                if self.path == "/api/admin/guarded" and role != "admin":
                    status, body = 403, "denied"
                elif self.path in ("/api/admin/guarded", "/api/admin/unguarded"):
                    status, body = 200, marker + " [redacted] synthetic-admin-result"
                else:
                    status, body = 404, "not-found"
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *_):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}"

            def get(path, role):
                try:
                    with urlopen(Request(url + path, headers={"X-Lab-Role": role}), timeout=2) as resp:
                        return resp.read().decode()
                except __import__("urllib.error", fromlist=["HTTPError"]).HTTPError as exc:
                    return exc.read().decode()

            baseline = get("/api/admin/unguarded", "admin")
            test = get("/api/admin/unguarded", "user")
            control = get("/api/admin/guarded", "user")
            self.assertIn(marker, baseline)
            self.assertIn(marker, test)
            self.assertNotIn(marker, control)
            self.assertIn("denied", control)
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder) / "lab"
                root.mkdir()
                cfg = scope_template("owned-loopback", [], "active")
                cfg["in_scope"] = [url]
                cfg["authz"] = {"probe_grants": [], "chain_grants": [],
                                "probe_budget": {"requests": 10, "per_host": 10}}
                (root / "scope.json").write_text(json.dumps(cfg))
                ctx = Recon(Campaign.load(root), log=lambda _: None)
                try:
                    aid = ctx.add_endpoint(url + "/api/admin/unguarded", "har", method="GET")
                    ctx.add_endpoint(url + "/api/admin/guarded", "har", method="GET")
                    for role, account in (("admin", "a"), ("user", "b")):
                        ctx.store.add_observation(
                            aid, "GET", account, {"query": [], "body": []}, 200, "owned-lab",
                            capture_key="lab:" + role,
                            context={"role": role, "tenant": "test", "workflow_state": "report",
                                     "csrf_meta": {"content_type": "text/plain", "auth": "header"}})
                    ledger = AuthzLedger(ctx)
                    target = next(t for t in ledger.plan()["targets"] if t["asset_id"] == aid)
                    cid = next(c["context_id"] for c in target["contexts"] if c["role"] == "user")
                    evidence = root / "evidence"
                    evidence.mkdir()
                    (evidence / "base.txt").write_text("admin authorized: " + baseline)
                    (evidence / "test.txt").write_text("low role unexpected: " + test)
                    (evidence / "control.txt").write_text("guarded low role: " + control)
                    result = ledger.record(cid, "ac-role", "observed", marker=marker,
                                           proof_basis="owned loopback guarded/unguarded control",
                                           requests=3, impact="admin", artifacts=[
                                               "baseline=evidence/base.txt", "test=evidence/test.txt",
                                               "control=evidence/control.txt"])
                    self.assertFalse(result["executed"])
                    self.assertEqual(ctx.store.request_count(), 0)
                    self.assertTrue(ledger.verify()["verified"])
                finally:
                    ctx.store.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
