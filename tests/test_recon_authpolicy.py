"""Auth-policy integration stays offline, source-labelled and non-promoting."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recon.authpolicy import AuthPolicyLedger
from recon.campaign import Campaign, ConfigError, scope_template, validate_auth_policy
from recon.cli import main
from recon.engagement import Engagement
from recon.fields import FieldLedger, module_of
from recon.pipeline import Recon
from recon.planning import digest, scope_revision
from recon.push import budget_snapshot, review


class AuthFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "campaign"
        self.root.mkdir()
        cfg = scope_template("owned-local-fixture", [], "active", ["POST"])
        cfg["in_scope"] = ["https://app.test/"]
        cfg["out_of_scope"] = []  # logout is excluded in the stock template until reviewed
        cfg["program_url"] = "https://program.test/rules"
        cfg["rules"] = ["Owned A/B test accounts only; no target traffic in this fixture"]
        cfg["auth_policy"] = {"policy_reviewed": "2026-11-21", "owned_accounts": ["a", "b"]}
        (self.root / "scope.json").write_text(json.dumps(cfg))
        self.ctx = Recon(Campaign.load(self.root), log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.auth = AuthPolicyLedger(self.ctx)
        self.fields = FieldLedger(self.ctx)

    def endpoint(self, path, method="POST", fields=("password",)):
        return self.ctx.add_endpoint("https://app.test" + path, "har", method=method,
                                     params=list(fields))

    def capture(self, aid, method="POST", account="a", workflow="first"):
        count = self.ctx.store.db.execute("SELECT count(*) FROM observations").fetchone()[0]
        self.ctx.store.add_observation(aid, method, account,
            {"query": [], "body": ["password"], "ids": {}}, 200, "har",
            capture_key=f"auth:{count}",
            context={"role": "user", "tenant": "owned", "workflow_state": workflow,
                     "csrf_meta": {"content_type": "application/json"}})

    def response(self, path, method="POST", status=200, body=b"owned_marker"):
        return self.ctx.store.record_request(method, "https://app.test" + path,
            status, "owned-fixture", [], {"Content-Type": "text/plain"},
            body=body, body_complete=True, basis="owned-lab")


class FieldConstraintTests(AuthFixture):
    def test_provenance_never_converts_client_claim_into_server_rule(self):
        aid = self.endpoint("/signup")
        self.fields.constraint(aid, "POST", "json", "password", "minlength", "12",
                               "html-attr", "page:signup")
        self.fields.constraint(aid, "POST", "json", "password", "minlength", "12",
                               "openapi", "spec:v1")
        with self.assertRaisesRegex(ValueError, "stored response"):
            self.fields.constraint(aid, "POST", "json", "password", "minlength", "12",
                                   "server-rejection", "response:1")
        rid = self.response("/signup", status=400)
        self.fields.constraint(aid, "POST", "json", "password", "minlength", "12",
                               "server-rejection", f"response:{rid}", rid)
        self.fields.constraint(aid, "POST", "json", "password", "minlength", "12",
                               "html-attr", "page:signup")
        claims = self.fields.constraints(aid)
        self.assertEqual(len(claims["claims"]), 3)
        self.assertEqual({c["source"] for c in claims["claims"]},
                         {"html-attr", "openapi", "server-rejection"})
        self.assertIn("not independently verified", self.fields.constraint(
            aid, "POST", "json", "password", "minlength", "12", "html-attr",
            "page:signup")["basis"])
        wrong = self.response("/password/reset", status=400)
        with self.assertRaisesRegex(ValueError, "not the declared"):
            self.fields.constraint(aid, "POST", "json", "password", "minlength", "12",
                                   "server-rejection", f"response:{wrong}", wrong)

    def test_surface_inventory_blocks_full_claim_until_individual_render_review(self):
        aid = self.endpoint("/profile", fields=("bio",))
        module = module_of("https://app.test/profile")
        first = self.fields.expect_surface(aid, "bio", "same-response", "xss-stored",
                                           "capture:1", "profile-preview", account="a")
        second = self.fields.expect_surface(aid, "bio", "admin-list", "xss-stored",
                                            "spec:1", "admin-view", account="a")
        for trigger in self.fields.matrix(module)["missing"]:
            self.fields.set_na(module, trigger, "not-present-in-this-fixture")
        with self.assertRaisesRegex(ValueError, "surface"):
            self.fields.claim(module, "full")
        marker = self.fields.canary(aid, "bio", account="a")["marker"]
        rid = self.response("/profile", body=("bio=" + marker).encode())
        self.fields.trace(marker)
        with self.assertRaisesRegex(ValueError, "no matching field canary"):
            self.fields.review_surface(second["expectation_id"], "reviewed", "not-this-render", rid)
        self.fields.review_surface(first["expectation_id"], "reviewed", "marker-in-profile", rid)
        self.assertEqual(self.fields.surface_matrix(module)["unresolved"], [second["expectation_id"]])
        self.fields.review_surface(second["expectation_id"], "n-a", "admin-render-not-deployed")
        self.assertTrue(self.fields.surface_matrix(module)["complete"])
        self.fields.claim(module, "full")
        self.ctx.store.db.execute("UPDATE requests SET status=201 WHERE id=?", (rid,))
        self.ctx.store.db.commit()
        self.assertIn(first["expectation_id"], self.fields.surface_matrix(module)["unresolved"])


class AuthLedgerTests(AuthFixture):
    def test_owned_labels_are_not_a_traffic_grant(self):
        with self.assertRaises(ConfigError):
            validate_auth_policy({"owned_accounts": ["a"]})
        with self.assertRaises(ConfigError):
            validate_auth_policy({"policy_reviewed": "2026-11-21", "owned_accounts": ["a", "a"]})
        self.assertEqual(self.ctx.policy.allowed_methods.count("POST"), 1)
        self.assertEqual(self.ctx.store.network_attempts(), 0)

    def test_per_method_workflow_and_entry_point_without_false_password_set(self):
        signup = self.endpoint("/signup")
        self.ctx.add_endpoint("https://app.test/signup", "har", method="GET")
        self.capture(signup, workflow="first")
        self.capture(signup, workflow="second")
        self.endpoint("/password/forgot")
        self.endpoint("/password/reset")
        self.endpoint("/logout")
        self.assertGreaterEqual(self.auth.sync()["operations_added"], 5)
        self.assertEqual(self.auth.sync()["operations_added"], 0)
        ops = self.auth.plan(limit=100)["operations"]
        signup_posts = [o for o in ops if o["entry_point"] == "signup" and o["method"] == "POST"
                        and o["account"] == "a"]
        self.assertEqual({o["workflow"] for o in signup_posts}, {"first", "second"})
        self.assertTrue(all("password-constraint:undeclared" in o["cases"] for o in signup_posts))
        self.assertTrue(all(not any(c.startswith("password-constraint:") for c in o["cases"]) for o in ops
                            if o["entry_point"] == "forgot-request" or
                            o["entry_point"] == "signup" and o["method"] == "GET"))
        self.assertTrue(any("logout-session" in o["cases"] for o in ops))
        self.assertFalse(any(o["entry_point"] == "password-reset" and
                             o["method"] == "GET" and o["cases"] for o in ops))

    def test_observed_requires_owned_context_effect_and_distinct_controls(self):
        aid = self.endpoint("/signup")
        self.capture(aid)
        self.auth.sync()
        self.fields.constraint(aid, "POST", "json", "password", "minlength", "12",
                               "html-attr", "page:signup")
        op = next(o for o in self.auth.plan()["operations"] if o["account"] == "a")
        case = next(iter(op["cases"]))
        rid = self.response("/signup")
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.auth.record(op["operation_id"], case, "observed",
                             {"baseline": rid, "test": rid, "control": rid, "readback": rid},
                             "weak-value-accepted")
        refs = {k: self.response("/signup" if k == "test" else "/owned-state", "POST")
                for k in ("baseline", "test", "control", "readback")}
        wrong_test = self.response("/owned-state")
        with self.assertRaisesRegex(ValueError, "exact operation"):
            self.auth.record(op["operation_id"], case, "observed",
                             {**refs, "test": wrong_test}, "wrong-operation")
        recorded = self.auth.record(op["operation_id"], case, "observed",
                                    refs, "owned-state-verified", source="owned-lab")
        self.assertFalse(recorded["finding_promoted"])
        self.assertEqual(self.auth.plan(op["operation_id"])["operations"][0]
                         ["cases"][case], "observed")
        self.assertTrue(self.auth.verify()["verified"])
        self.ctx.store.db.execute("UPDATE requests SET status=401 WHERE id=?", (refs["control"],))
        self.ctx.store.db.commit()
        self.assertEqual(self.auth.plan(op["operation_id"])["operations"][0]
                         ["cases"][case], "stale")
        self.assertFalse(self.auth.verify()["verified"])

    def test_password_rule_and_field_cells_do_not_collapse(self):
        aid = self.endpoint("/signup", fields=("password", "passwordConfirmation"))
        self.capture(aid)
        self.auth.sync()
        op = next(o for o in self.auth.plan()["operations"] if o["account"] == "a")
        with self.assertRaisesRegex(ValueError, "sourced declared constraint"):
            self.auth.record(op["operation_id"], "password-constraint:undeclared", "observed",
                             {}, "no-rule-source")
        for field, kind, value in (("password", "minlength", "12"),
                                   ("password", "complexity", "letters-and-digits"),
                                   ("passwordConfirmation", "minlength", "12")):
            self.fields.constraint(aid, "POST", "json", field, kind, value,
                                   "html-attr", "page:signup")
        keys = list(self.auth.plan(op["operation_id"])["operations"][0]["cases"])
        self.assertEqual(len(keys), 3)
        self.assertEqual(len(set(keys)), 3)
        refs = {k: self.response("/signup" if k == "test" else "/owned-state")
                for k in ("baseline", "test", "control", "readback")}
        self.auth.record(op["operation_id"], keys[0], "observed", refs, "one-rule-reviewed")
        states = self.auth.plan(op["operation_id"])["operations"][0]["cases"]
        self.assertEqual(states[keys[0]], "observed")
        self.assertEqual(list(states.values()).count("untested"), 2)

    def test_case_relation_tamper_and_untrusted_capture_account_cannot_complete(self):
        aid = self.endpoint("/signup")
        self.capture(aid, account="real-person@example.test")
        self.auth.sync()
        self.assertTrue(all(o["account"] == "unknown" for o in self.auth.plan()["operations"]))
        self.fields.constraint(aid, "POST", "json", "password", "minlength", "12",
                               "html-attr", "page:signup")
        op = self.auth.declare(aid, "https://app.test/signup", "POST", "signup",
                               "operator:owned", account="a")["operation_id"]
        case = next(iter(self.auth.plan(op)["operations"][0]["cases"]))
        refs = {k: self.response("/signup" if k == "test" else "/owned-state")
                for k in ("baseline", "test", "control", "readback")}
        self.auth.record(op, case, "observed", refs, "owned-state-check")
        self.ctx.store.db.execute("UPDATE auth_policy_case_events SET case_id='login-rate-limit' "
                                  "WHERE operation_id=?", (op,))
        self.ctx.store.db.commit()
        self.assertFalse(self.auth.verify()["verified"])
        self.assertEqual(self.auth.plan(op)["operations"][0]["cases"][case],
                         "untested")

    def test_invalidation_requires_event_and_post_event_control(self):
        aid = self.endpoint("/password/change")
        op = self.auth.declare(aid, "https://app.test/password/change", "POST",
                               "password-change", "capture:1", account="a")["operation_id"]
        roles = {r: self.response("/password/change" if r == "event" else "/profile")
                 for r in ("pre-event", "event", "post-event", "invalid-control")}
        with self.assertRaisesRegex(ValueError, "distinct before"):
            self.auth.record(op, "change-sessions", "observed",
                             {k: v for k, v in roles.items() if k != "invalid-control"},
                             "old-session-readback")
        self.auth.record(op, "change-sessions", "observed", roles, "old-session-readback")
        self.assertIn("change-reset-links", self.auth.plan(op)["operations"][0]["cases"])
        self.assertEqual(self.auth.plan(op)["operations"][0]["cases"]["change-reset-links"],
                         "untested")

    def test_private_derivation_is_a_candidate_not_token_proof(self):
        private = self.root / ".recon/private/auth-policy"
        private.mkdir(parents=True)
        path = private / "samples.json"
        raw_values = ("123456789001", "123456789002")
        path.write_text(json.dumps({"schema_version": 1, "kind": "reset-token",
            "samples": [{"account": "a", "value": raw_values[0]},
                        {"account": "b", "value": raw_values[1]}]}))
        with self.assertRaisesRegex(ValueError, "mode 0600"):
            self.auth.derive(".recon/private/auth-policy/samples.json")
        with self.assertRaisesRegex(ValueError, "campaign-local"):
            self.auth.derive(".recon/private/auth-policy/../../../../escape.json")
        os.chmod(path, 0o600)
        result = self.auth.derive(".recon/private/auth-policy/samples.json")
        self.assertTrue(result["numeric_monotonic"])
        self.assertFalse(result["finding_promoted"])
        self.assertTrue(self.auth.verify()["verified"])
        db_dump = " ".join(self.ctx.store.db.iterdump())
        for value in raw_values:
            self.assertNotIn(value, db_dump)
            self.assertNotIn(value, json.dumps(result))
        self.assertTrue(path.is_file())  # operator owns the private source; no automatic deletion

    def test_cli_and_debt_exact_push_binding_without_network(self):
        aid = self.endpoint("/signup")
        self.capture(aid)
        self.fields.constraint(aid, "POST", "json", "password", "minlength", "12",
                               "html-attr", "page:signup")
        surface = self.fields.expect_surface(aid, "password", "admin-view", "xss-stored",
                                             "owned-spec:1", "separate-admin-render")
        self.ctx.refresh_coverage()
        eng = Engagement(self.ctx, "auth-review")
        eng.init()
        with patch.object(self.ctx.client, "request", side_effect=AssertionError("no traffic")):
            debt = eng.reconcile()
        op = next(o for o in self.auth.plan()["operations"] if o["account"] == "a")
        case = next(iter(op["cases"]))
        debt_id = f"auth-case:{op['operation_id']}:{case}"
        self.assertIn(debt_id, {d["id"] for d in debt["items"]})
        self.assertIn(f"surface:{surface['expectation_id']}", {d["id"] for d in debt["items"]})
        manifest = {"schema_version": 1, "scope_sha256": scope_revision(self.ctx),
                    "budget_sha256": digest(budget_snapshot(self.ctx)), "pushes": [{
                        "class": "security-misconfiguration", "asset_id": aid,
                        "asset_sha256": digest(self.ctx.store.get_asset(aid)),
                        "endpoint": op["url"], "method": "POST", "skill": "hunt-security-misconfig",
                        "model": "offline-review", "intent": "compare owned password rule",
                        "predicate": {"type": "status_is", "expected": 200}, "poe_target": 1,
                        "request_budget": 2, "debt_items": [debt_id], "reason": "owned operation"}]}
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest))
        self.assertTrue(review(self.ctx, path, eng)["validated"])
        manifest["pushes"][0]["method"] = "GET"
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "exact asset/method"):
            review(self.ctx, path, eng)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["authpolicy", "status", str(self.root)]), 0)
            self.assertEqual(main(["fields", "constraints", str(self.root),
                                   "--asset-id", str(aid)]), 0)
        self.assertEqual(self.ctx.store.network_attempts(), 0)


if __name__ == "__main__":
    unittest.main()
