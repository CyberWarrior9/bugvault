"""CSRF action ledger (recon/csrf.py) and value-free capture metadata (recon/csrfmeta.py).

Offline only: inventory from captures/forms/JS/specs, per-context case readiness,
record rules, facet-scoped reopening, per-case effort, status/report/CLI, importer
metadata privacy, and the skill reference staying in sync with the engine.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.cli import main
from recon.csrf import CASES, CASE_BY_ID, CsrfLedger, site_relationship
from recon.csrfmeta import cookie_applies, graphql_operations, parse_set_cookie, request_meta
from recon.extract import parse_page
from recon.findings import Findings
from recon.har import import_har
from recon.pipeline import Recon
from recon.report import write_reports
from recon.score import applicable_classes
from recon.specs import import_openapi
from tests.test_recon import write_campaign

REPO = Path(__file__).resolve().parents[1]
SECRET = "TOPSECRETVALUE42"
LAX = [("Set-Cookie", f"sid={SECRET}; Path=/; HttpOnly; SameSite=Lax")]


class CsrfFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [],
                                   in_scope=["acme.test", "admin.acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.led = CsrfLedger(self.ctx)
        self.seq = 0

    def observe(self, aid, method="POST", account="victim", headers=(("Cookie", f"sid={SECRET}"),),
                body=("email",), query=(), content_type="application/x-www-form-urlencoded",
                response=LAX, role="user", workflow="settings"):
        self.seq += 1
        meta = request_meta(list(headers), content_type, list(query), list(body), list(response))
        self.ctx.store.add_observation(
            aid, method, account, {"query": list(query), "body": list(body), "ids": {}, "auth": True},
            200, "har", capture_key=f"t:{self.seq}",
            context={"role": role, "workflow_state": workflow, "csrf_meta": meta})

    def email_action(self, **kwargs):
        aid = self.ctx.add_endpoint("https://acme.test/account/email", "har", method="POST",
                                    params=["email"])
        self.observe(aid, **kwargs)
        self.led.sync()
        return aid

    def artifact(self, name, text):
        path = self.root / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return f"evidence/{name}"

    def readbacks(self, changed=True):
        before = self.artifact(f"before-{self.seq}.json", '{"email":"v@lab"}')
        after = self.artifact(f"after-{self.seq}.json",
                              '{"email":"a@lab"}' if changed else '{"email":"v@lab"}')
        self.seq += 1
        return [f"before={before}", f"after={after}",
                f"request={self.artifact(f'req-{self.seq}.txt', 'POST /account/email')}"]

    def context_id(self, route="/account/email", origin="https://acme.test", **match):
        plan = self.led.plan(limit=500)
        action = next(a for a in plan["actions"] if a["route"] == route and a["origin"] == origin
                      and a["selector"] == match.pop("selector", ""))
        ctx = next(c for c in action["contexts"]
                   if all(c[k] == v for k, v in match.items()) and not c["superseded"])
        return ctx["context_id"]

    def card(self, context_id, case):
        for action in self.led.plan(limit=500)["actions"]:
            for ctx in action["contexts"]:
                if ctx["context_id"] == context_id:
                    return next(c for c in ctx["cases"] if c["case"] == case)
        raise AssertionError("context not found")

    def baseline(self, context_id):
        return self.led.record(context_id, "baseline", "observed", artifacts=self.readbacks())


class MetadataTests(unittest.TestCase):
    def test_set_cookie_keeps_attributes_never_the_value(self):
        lax = parse_set_cookie(f"sid={SECRET}; Path=/; Secure; HttpOnly; SameSite=Lax")
        omitted = parse_set_cookie(f"pref={SECRET}; Domain=.Acme.test; Max-Age=60")
        self.assertEqual(lax["samesite"], "lax")
        self.assertIsNone(omitted["samesite"])           # omitted is not explicit Lax
        self.assertEqual(omitted["domain"], "acme.test")
        self.assertTrue(omitted["persistent"])
        self.assertEqual(parse_set_cookie("__Host-s=1; Secure; Path=/")["prefix"], "__Host-")
        self.assertEqual(parse_set_cookie("x=1; SameSite=bogus")["samesite"], "invalid")
        self.assertIsNone(parse_set_cookie("no-equals-sign"))
        self.assertNotIn(SECRET, json.dumps([lax, omitted]))

    def test_authority_mechanisms(self):
        cases = {
            "cookie": [("Cookie", f"sid={SECRET}")],
            "browser-auth": [("Authorization", f"Basic {SECRET}")],
            "header": [("Authorization", f"Bearer {SECRET}")],
            "cookie+header": [("Cookie", "sid=1"), ("X-API-Key", SECRET)],
            "none": [("Accept", "text/html")],
        }
        for expected, headers in cases.items():
            with self.subTest(expected=expected):
                meta = request_meta(headers)
                self.assertEqual(meta["auth"], expected)
                self.assertNotIn(SECRET, json.dumps(meta))

    def test_tokens_flags_and_origins_are_value_free(self):
        meta = request_meta(
            [("Cookie", f"csrftoken={SECRET}; sessionid={SECRET}"), ("X-CSRFToken", SECRET),
             ("X-Requested-With", "XMLHttpRequest"), ("Origin", "https://App.acme.test"),
             ("Referer", f"https://acme.test/reset?token={SECRET}#frag"),
             ("Sec-Fetch-Site", "same-site"), (":authority", "acme.test")],
            "application/json; charset=utf-8", ["page"], ["csrfmiddlewaretoken", "email"])
        self.assertEqual(meta["token_channels"], ["body:csrfmiddlewaretoken", "header:x-csrftoken"])
        self.assertEqual(meta["header_flags"], ["x-requested-with"])
        self.assertEqual(meta["csrf_cookie_names"], ["csrftoken"])
        self.assertEqual(meta["origin"], "https://app.acme.test")
        self.assertEqual(meta["referer_origin"], "https://acme.test")  # path/query dropped
        self.assertEqual(meta["sec_fetch"], {"site": "same-site"})
        self.assertEqual(meta["content_type"], "application/json")
        text = json.dumps(meta)
        self.assertNotIn(SECRET, text)
        self.assertNotIn("reset", text)

    def test_cookie_scope(self):
        host_only = parse_set_cookie("a=1")
        domain = parse_set_cookie("a=1; Domain=acme.test")
        self.assertTrue(cookie_applies(host_only, "app.acme.test", "app.acme.test"))
        self.assertFalse(cookie_applies(host_only, "login.acme.test", "app.acme.test"))
        self.assertTrue(cookie_applies(domain, "login.acme.test", "app.acme.test"))
        self.assertFalse(cookie_applies(domain, "login.acme.test", "acme.test.evil"))

    def test_site_relationship_is_schemeful_and_not_origin(self):
        rel = site_relationship
        self.assertEqual(rel("https://app.acme.test", "https://app.acme.test"), "same-origin")
        self.assertEqual(rel("https://app.acme.test", "https://app.acme.test:8443"), "same-site")
        self.assertEqual(rel("https://app.acme.test", "https://blog.acme.test"), "same-site")
        self.assertEqual(rel("https://app.acme.test", "http://blog.acme.test"), "cross-site")
        self.assertEqual(rel("https://app.acme.test", "https://acme-test.example"), "cross-site")
        self.assertEqual(rel("https://shop.example.co.uk", "https://other.co.uk"), "cross-site")
        self.assertEqual(rel("https://a.shop.co.uk", "https://b.shop.co.uk"), "same-site")
        self.assertEqual(rel("wss://app.acme.test", "https://blog.acme.test"), "same-site")
        self.assertEqual(rel("https://10.0.0.1", "https://10.0.0.2"), "cross-site")
        self.assertEqual(rel("https://app.acme.test", "null"), "opaque")


class InventoryTests(CsrfFixture):
    def build_surface(self):
        self.email_action()
        self.ctx.add_endpoint("https://acme.test/api/logout", "js", method="POST")
        self.ctx.add_endpoint("https://acme.test/items/7/delete", "js")
        self.ctx.add_endpoint("https://acme.test/api/orders", "js", method="GET", params=["page"])
        self.ctx.add_endpoint("https://admin.acme.test/account/email", "js", method="POST")
        self.ctx.add_endpoint("https://acme.test/graphql", "js", method="POST")
        svc = self.ctx.service_for("https://acme.test/")
        self.ctx.store.update_attrs(svc, {"graphql_ops": ["mutation CreateSnippet", "query Viewer"]})
        self.ctx.add_endpoint("wss://acme.test/hubs/chat", "js")
        self.ctx.add_endpoint("https://acme.test/api/v3/settings/update", "js", method="POST")
        return self.led.sync()

    def test_actions_cover_fieldless_get_mutations_graphql_realtime_and_hosts(self):
        self.build_surface()
        actions = {(a["method"], a["origin"] + a["route"], a["selector"]):
                   (a["kind"], a["basis"], a["fieldless"])
                   for a in self.led.plan(limit=500)["actions"]}
        expected = {
            ("POST", "https://acme.test/account/email", ""): ("http", "captured", False),
            ("POST", "https://admin.acme.test/account/email", ""): ("http", "declared", True),
            ("POST", "https://acme.test/api/logout", ""): ("http", "declared", True),
            ("UNKNOWN", "https://acme.test/items/{id}/delete", ""): ("http", "declared", True),
            ("POST", "https://acme.test/graphql", ""): ("graphql", "declared", True),
            ("POST", "https://acme.test/graphql", "mutation CreateSnippet"): ("graphql", "declared", False),
            ("UNKNOWN", "wss://acme.test/hubs/chat", ""): ("realtime", "declared", True),
            ("POST", "https://acme.test/api/v3/settings/update", ""): ("http", "declared", True),
        }
        self.assertEqual(actions, expected)  # reads, queries and version siblings are not actions

    def test_sync_is_idempotent_and_contexts_split_by_identity(self):
        aid = self.email_action()
        self.observe(aid, account="victim", role="admin")
        self.observe(aid, account="attacker")
        first = self.led.sync()
        self.assertEqual(first["contexts_added"], 2)
        again = self.led.sync()
        self.assertEqual((again["actions_added"], again["contexts_added"], again["contexts_changed"],
                          again["actions_updated"]), (0, 0, 0, 0))
        contexts = self.led.plan()["actions"][0]["contexts"]
        self.assertEqual(sorted((c["account"], c["role"]) for c in contexts),
                         [("attacker", "user"), ("victim", "admin"), ("victim", "user")])
        self.assertFalse(again["executed"])

    def test_capture_supersedes_declared_context(self):
        aid = self.ctx.add_endpoint("https://acme.test/api/profile", "js", method="POST")
        self.led.sync()
        declared = self.led.plan()["actions"][0]["contexts"]
        self.assertEqual([c["basis"] for c in declared], ["declared"])
        self.observe(aid, body=("bio",))
        self.led.sync()
        contexts = self.led.plan()["actions"][0]["contexts"]
        by_basis = {c["basis"]: c for c in contexts}
        self.assertTrue(by_basis["declared"]["superseded"])
        self.assertFalse(by_basis["captured"]["superseded"])
        self.assertEqual(self.led.plan()["actions"][0]["basis"], "captured")


class ReadinessTests(CsrfFixture):
    def test_baseline_gates_attack_cases(self):
        self.email_action()
        cid = self.context_id()
        self.assertEqual(self.card(cid, "baseline")["readiness"], "ready")
        self.assertEqual(self.card(cid, "token-enforcement")["readiness"], "waiting-baseline")
        self.assertEqual(self.card(cid, "graphql-operation")["readiness"], "n-a-suggested")
        self.assertEqual(self.card(cid, "effect-handoff")["readiness"], "waiting-effect")
        self.baseline(cid)
        card = self.card(cid, "token-enforcement")
        self.assertEqual(card["readiness"], "ready")
        # no token captured: only the complete-omission variant applies
        self.assertEqual(card["open_variants"], ["omit-all-channels"])
        self.assertEqual(self.card(cid, "token-context")["readiness"], "n-a-suggested")

    def test_authority_drives_ambient_families(self):
        aid = self.ctx.add_endpoint("https://acme.test/api/settings", "har", method="POST",
                                    params=["theme"])
        self.observe(aid, account="bearer", headers=(("Authorization", f"Bearer {SECRET}"),),
                     body=("theme",))
        self.observe(aid, account="sanitized", headers=(), body=("theme",))
        self.led.sync()
        bearer = self.context_id("/api/settings", account="bearer")
        sanitized = self.context_id("/api/settings", account="sanitized")
        for cid in (bearer, sanitized):
            self.baseline(cid)
        self.assertEqual(self.card(bearer, "cookie-delivery")["readiness"], "n-a-suggested")
        self.assertIn("explicitly attached", self.card(bearer, "cookie-delivery")["reason"])
        self.assertEqual(self.card(sanitized, "cookie-delivery")["readiness"], "needs-confirmation")
        self.assertTrue(self.card(sanitized, "cookie-delivery")["open"])

    def test_families_follow_route_kind_and_tokens(self):
        link = self.ctx.add_endpoint("https://acme.test/oauth/link/callback", "har", method="POST",
                                     params=["code", "state"])
        self.observe(link, body=("code", "state"))
        gql = self.ctx.add_endpoint("https://acme.test/graphql", "har", method="POST",
                                    params=["query"])
        self.observe(gql, body=("query", "csrfmiddlewaretoken"), content_type="application/json",
                     headers=(("Cookie", "sid=1; csrftoken=2"),))
        self.led.sync()
        link_ctx, gql_ctx = self.context_id("/oauth/link/callback"), self.context_id("/graphql")
        for cid in (link_ctx, gql_ctx):
            self.baseline(cid)
        identity = self.card(link_ctx, "identity-transaction")
        self.assertEqual(identity["readiness"], "ready")
        states = {v["id"]: v["state"] for v in identity["variants"]}
        self.assertEqual(states["login-csrf"], "n-a-suggested")
        self.assertEqual(states["link-callback-swap"], "open")
        self.assertEqual(self.card(gql_ctx, "graphql-operation")["readiness"], "ready")
        self.assertEqual(self.card(gql_ctx, "cookie-binding")["readiness"], "ready")
        self.assertEqual(self.card(gql_ctx, "token-context")["readiness"], "ready")
        rep = {v["id"]: v["state"] for v in self.card(gql_ctx, "representation")["variants"]}
        self.assertEqual(rep["preflight-path"], "open")  # JSON is non-simple

    def test_baseline_n_a_closes_siblings(self):
        aid = self.ctx.add_endpoint("https://acme.test/search", "har", method="POST", params=["q"])
        self.observe(aid, body=("q",))
        self.led.sync()
        cid = self.context_id("/search")
        with self.assertRaises(ValueError):
            self.led.record(cid, "baseline", "n-a")  # needs a reason
        self.led.record(cid, "baseline", "n-a", note="read-only search POST: no state changes")
        card = self.card(cid, "cookie-delivery")
        self.assertEqual(card["readiness"], "n-a-baseline")
        self.assertFalse(card["open"])


class RecordTests(CsrfFixture):
    def attack(self, cid, **kw):
        base = {"variant": "top-level-post", "initiator": "cross-site",
                "initiator_origin": "https://attacker-lab.example", "delivery": "form-post",
                "browser": "Chromium lab", "artifacts": self.readbacks()}
        base.update(kw)
        case = base.pop("case", "cookie-delivery")
        return self.led.record(cid, case, "observed", **base)

    def test_observed_rules(self):
        self.email_action()
        cid = self.context_id()
        with self.assertRaisesRegex(ValueError, "baseline"):
            self.attack(cid)
        with self.assertRaisesRegex(ValueError, "state change"):
            self.led.record(cid, "baseline", "observed", artifacts=self.readbacks(changed=False))
        self.baseline(cid)
        bad = {
            "replay carries no browser initiator": dict(attempt_kind="replay"),
            "initiator origin equals the target": dict(initiator_origin="https://acme.test"),
            "denied preflight": dict(case="representation", variant="text-plain",
                                     delivery="fetch", preflight="denied"),
            "same-site needs prerequisite": dict(variant="same-site-sibling", initiator="same-site",
                                                 initiator_origin="https://blog.acme.test"),
            "computed same-site needs prerequisite": dict(
                variant="same-site-sibling", initiator_origin="https://blog.acme.test"),
            "delivery mode": dict(delivery=""),
            "request artifact": dict(artifacts=self.readbacks()[:2]),
            "unknown variant": dict(variant="bogus"),
        }
        for label, overrides in bad.items():
            with self.subTest(label), self.assertRaises(ValueError):
                self.attack(cid, **overrides)
        ok = self.attack(cid, variant="same-site-sibling", initiator="same-site",
                         initiator_origin="https://blog.acme.test",
                         prerequisite="owned lab sibling host")
        self.assertEqual(ok["relationship"], "same-site")
        self.assertFalse(ok["finding_promoted"])
        self.assertEqual(self.card(cid, "cookie-delivery")["outcome"], "observed")
        self.assertEqual(self.card(cid, "effect-handoff")["readiness"], "ready")
        stored = self.root / ok["artifacts"][0]["path"]
        self.assertTrue(stored.is_file())
        self.assertEqual(stored.stat().st_mode & 0o777, 0o600)
        Findings(self.ctx)  # ensures the findings schema; the ledger never writes there
        self.assertEqual(self.ctx.store.db.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 0)

    def test_conflicting_relationship_is_flagged_not_rewritten(self):
        self.email_action()
        cid = self.context_id()
        result = self.led.record(cid, "origin-metadata", "attempted", variant="cross-site-origin",
                                 initiator="cross-site", initiator_origin="https://shop.acme.test")
        self.assertTrue(result["relationship_conflict"])
        self.assertEqual(result["relationship"], "same-site")
        with self.assertRaises(ValueError):  # opaque initiators use the null origin
            self.led.record(cid, "origin-metadata", "attempted", variant="null-origin",
                            initiator="opaque", initiator_origin="https://x.example")

    def test_realtime_needs_protected_messages(self):
        aid = self.ctx.add_endpoint("wss://acme.test/hubs/admin", "har", method="GET")
        self.observe(aid, method="GET", body=(), content_type="")
        self.led.sync()
        cid = self.context_id("/hubs/admin", origin="wss://acme.test")
        self.baseline(cid)
        common = dict(variant="message-authorization", initiator="cross-site",
                      initiator_origin="https://attacker-lab.example", delivery="websocket")
        with self.assertRaisesRegex(ValueError, "101"):
            self.led.record(cid, "realtime-authority", "observed", artifacts=self.readbacks(), **common)
        frames = self.artifact("frames.json", '[{"invoke":"DeleteUser"}]')
        result = self.led.record(cid, "realtime-authority", "observed",
                                 artifacts=self.readbacks() + [f"messages={frames}"], **common)
        self.assertEqual(result["state"], "observed")

    def test_case_negative_needs_every_variant(self):
        self.email_action(headers=(("Cookie", "sid=1"), ("X-CSRF-Token", SECRET)))
        cid = self.context_id()
        self.baseline(cid)
        resp = self.artifact("403.html", "forbidden")
        with self.assertRaisesRegex(ValueError, "omit-all-channels"):
            self.led.record(cid, "token-enforcement", "negative", note="rejected",
                            artifacts=[f"response={resp}"])
        variants = [v[0] for v in CASE_BY_ID["token-enforcement"]["variants"]]
        for variant in variants[:-1]:
            self.led.record(cid, "token-enforcement", "negative", variant=variant,
                            initiator="cross-site", initiator_origin="https://attacker-lab.example",
                            delivery="form-post", note="403, readback unchanged",
                            artifacts=[f"response={resp}"])
        self.led.record(cid, "token-enforcement", "n-a", variant=variants[-1],
                        note="parser rejects duplicate parameters outright")
        card = self.card(cid, "token-enforcement")
        self.assertEqual((card["outcome"], card["open"]), ("negative", False))
        self.led.record(cid, "token-enforcement", "negative", note="all variants rejected",
                        artifacts=[f"response={resp}"])

    def test_artifact_rules_and_verification(self):
        self.email_action()
        cid = self.context_id()
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("x")
        with self.assertRaises(ValueError):
            self.led.record(cid, "baseline", "attempted", artifacts=[f"before={outside}"])
        with self.assertRaises(ValueError):
            self.led.record(cid, "baseline", "attempted", artifacts=["shot=evidence/x"])
        result = self.baseline(cid)
        self.assertEqual(self.led.verify_artifacts()["missing_or_modified"], [])
        stored = self.root / result["artifacts"][0]["path"]
        stored.chmod(0o600)
        stored.write_text("tampered")
        bad = self.led.verify_artifacts()["missing_or_modified"]
        self.assertEqual([b["role"] for b in bad], ["before"])


class FreshnessAndEffortTests(CsrfFixture):
    def test_cookie_policy_change_reopens_only_cookie_dependent_cases(self):
        self.email_action()
        cid = self.context_id()
        self.baseline(cid)
        self.led.record(cid, "cookie-delivery", "observed", variant="same-site-sibling",
                        initiator="same-site", initiator_origin="https://blog.acme.test",
                        delivery="form-post", prerequisite="owned lab sibling",
                        artifacts=self.readbacks())
        self.led.record(cid, "token-enforcement", "attempted", variant="omit-all-channels",
                        initiator="cross-site", initiator_origin="https://attacker-lab.example",
                        delivery="form-post")
        login = self.ctx.add_endpoint("https://acme.test/login", "har", method="POST",
                                      params=["user"])
        self.observe(login, body=("user",),
                     response=[("Set-Cookie", "sid=x; Path=/; SameSite=None; Secure")])
        sync = self.led.sync()
        self.assertGreaterEqual(sync["contexts_changed"], 1)
        self.assertEqual(self.card(cid, "cookie-delivery")["outcome"], "stale")
        self.assertTrue(self.card(cid, "cookie-delivery")["open"])
        self.assertEqual(self.card(cid, "token-enforcement")["outcome"], "in-progress")
        self.assertEqual(self.card(cid, "baseline")["outcome"], "observed")
        stale = self.led.status()["stale_cases"]
        self.assertIn({"action_id": 1, "context_id": cid, "case": "cookie-delivery"}, stale)

    def test_effort_cap_is_per_case(self):
        self.email_action()
        cid = self.context_id()
        self.baseline(cid)
        for _ in range(3):
            self.led.record(cid, "origin-metadata", "attempted", variant="lookalike-origin",
                            initiator="cross-site", initiator_origin="https://acme.test.lab.example",
                            delivery="form-post")
        self.assertTrue(self.card(cid, "origin-metadata")["effort_cap_reached"])
        self.assertFalse(self.card(cid, "cookie-delivery")["effort_cap_reached"])
        self.assertTrue(self.card(cid, "cookie-delivery")["open"])
        capped = self.led.status()["effort_cap_reached"]
        self.assertEqual([c["case"] for c in capped], ["origin-metadata"])


class StatusReportCliTests(CsrfFixture):
    def test_status_lists_coarse_rows_with_open_cases(self):
        aid = self.email_action()
        self.ctx.refresh_coverage()
        self.ctx.store.set_coverage(aid, "csrf", "tested", "three attempts")
        status = self.led.status()
        self.assertEqual(status["coarse_rows_with_open_cases"][0]["asset_id"], aid)
        self.assertEqual(status["hosts"][0]["origin"], "https://acme.test")
        self.assertGreater(status["open_cases"], 0)

    def test_coverage_report_section(self):
        self.email_action()
        self.ctx.refresh_coverage()
        coverage = next(p for p in write_reports(self.ctx) if p.name == "coverage.md")
        text = coverage.read_text()
        self.assertIn("## CSRF action coverage", text)
        self.assertIn("| https://acme.test |", text)
        self.assertIn("### Next CSRF cases", text)
        row = [r for r in text.splitlines() if "/account/email" in r and "| csrf |" in r]
        self.assertTrue(row and row[0].rstrip().endswith("| hunt-csrf |"))

    def test_offline_only(self):
        aid = self.email_action()
        before = self.ctx.store.request_count()
        with patch("socket.socket", side_effect=AssertionError("network")), \
                patch("subprocess.Popen", side_effect=AssertionError("subprocess")):
            self.led.sync()
            cid = self.context_id()
            self.led.plan()
            self.baseline(cid)
            self.led.status()
            self.led.verify_artifacts()
        self.assertEqual(self.ctx.store.request_count(), before)
        self.assertTrue(aid)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(["csrf", *args])
        return rc, out.getvalue(), err.getvalue()

    def test_cli_flow(self):
        self.email_action()
        self.ctx.store.close()
        rc, out, _ = self.run_cli("sync", str(self.root))
        self.assertEqual(rc, 0)
        self.assertFalse(json.loads(out)["executed"])
        rc, out, _ = self.run_cli("plan", str(self.root), "--action", "1")
        plan = json.loads(out)
        cid = plan["actions"][0]["contexts"][0]["context_id"]
        artifacts = self.readbacks()
        args = ["record", str(self.root), "--context", str(cid), "--case", "baseline",
                "--state", "observed"]
        for a in artifacts:
            args += ["--artifact", a]
        rc, out, _ = self.run_cli(*args)
        self.assertEqual((rc, json.loads(out)["state"]), (0, "observed"))
        rc, _, err = self.run_cli("record", str(self.root), "--context", str(cid), "--case",
                                  "cookie-delivery", "--state", "observed")
        self.assertEqual(rc, 1)
        self.assertIn("readback", err)
        rc, out, _ = self.run_cli("status", str(self.root), "--host", "acme.test")
        self.assertEqual(json.loads(out)["hosts"][0]["origin"], "https://acme.test")
        rc, out, _ = self.run_cli("verify", str(self.root))
        self.assertEqual(json.loads(out)["missing_or_modified"], [])
        self.ctx = Recon(self.camp, log=lambda _: None)  # reopen for cleanup
        self.addCleanup(self.ctx.store.close)


class DiscoveryTests(CsrfFixture):
    def test_score_seeds_get_mutations_and_realtime(self):
        def classes(value, methods=(), params=()):
            return applicable_classes({"value": value, "attrs": {"methods": list(methods),
                                                                 "params": list(params)}})
        self.assertIn("csrf", classes("https://acme.test/items/7/delete"))
        self.assertIn("csrf", classes("https://acme.test/newsletter", ["GET"], ["action"]))
        self.assertIn("csrf", classes("wss://acme.test/ws"))
        self.assertNotIn("csrf", classes("https://acme.test/api/updates", ["GET"], ["page"]))
        self.assertNotIn("csrf", classes("https://acme.test/settings", ["GET"]))

    def test_graphql_operations_are_names_only(self):
        body = json.dumps({"query": "mutation updateEmail($e: String!) { updateEmail(email: $e) { id } }",
                           "variables": {"e": SECRET}, "operationName": "updateEmail"})
        self.assertEqual(graphql_operations("https://acme.test/graphql", body), ["mutation updateEmail"])
        self.assertEqual(graphql_operations("https://acme.test/graphql?query=mutation%20addApiKey%7Bx%7D", None),
                         ["mutation addApiKey"])
        batch = json.dumps([{"operationName": "Viewer", "extensions": {"persistedQuery": {}}},
                            {"query": "mutation { reset }"}])
        self.assertEqual(graphql_operations("https://acme.test/graphql", batch),
                         ["mutation (anonymous)", "persisted Viewer"])
        self.assertNotIn(SECRET, json.dumps(graphql_operations("https://acme.test/graphql", body)))

    def test_captured_graphql_mutation_attaches_to_its_action_and_camelcase_ranks(self):
        aid = self.ctx.add_endpoint("https://acme.test/graphql", "har", method="POST",
                                    params=["query", "operationName"])
        svc = self.ctx.service_for("https://acme.test/")
        self.ctx.store.update_attrs(svc, {"graphql_ops": ["mutation updateEmail",
                                                          "mutation addApiKey"]})
        meta = request_meta([("Cookie", "sid=1")], "application/json", [], ["query"], [],
                            graphql_ops=["mutation updateEmail"])
        self.ctx.store.add_observation(aid, "POST", "victim", {"query": [], "body": ["query"],
                                                               "ids": {}, "auth": True},
                                       200, "har", capture_key="gql:1",
                                       context={"csrf_meta": meta})
        self.led.sync()
        by_selector = {a["selector"]: a for a in self.led.plan()["actions"]}
        self.assertEqual((by_selector["mutation updateEmail"]["basis"],
                          by_selector["mutation updateEmail"]["priority"]), ("captured", "identity"))
        self.assertEqual((by_selector["mutation addApiKey"]["basis"],
                          by_selector["mutation addApiKey"]["priority"]), ("declared", "security"))
        self.assertIn("csrf", applicable_classes({"value": "https://acme.test/api/deleteItem",
                                                  "attrs": {"methods": ["GET"]}}))

    def test_form_enctype_and_token_fields_reach_declared_contexts(self):
        page = parse_page('<form method="post" action="/avatar" enctype="Multipart/Form-Data">'
                          '<input type="hidden" name="authenticity_token" value="' + SECRET + '">'
                          '<input name="file"></form><form action="/search"><input name="q"></form>')
        post, get = page.forms
        self.assertEqual((post["enctype"], post["token_fields"]),
                         ("multipart/form-data", ["authenticity_token"]))
        self.assertEqual(get["token_fields"], [])
        self.ctx.add_endpoint("https://acme.test/avatar", "form", method="POST",
                              params=post["inputs"],
                              extra={"form_enctypes": [post["enctype"]],
                                     "csrf_token_fields": post["token_fields"]})
        self.led.sync()
        ctx = self.led.plan()["actions"][0]["contexts"][0]
        self.assertEqual(ctx["content_type"], "multipart/form-data")
        self.assertIn("body:authenticity_token", ctx["token_channels"])

    def test_har_import_keeps_metadata_without_values(self):
        har = {"log": {"entries": [{
            "request": {"method": "POST", "url": "https://acme.test/account/email",
                        "headers": [{"name": "Cookie", "value": f"sid={SECRET}"},
                                    {"name": "X-CSRF-Token", "value": SECRET},
                                    {"name": "Origin", "value": "https://acme.test"},
                                    {"name": "Referer", "value": f"https://acme.test/s?t={SECRET}"},
                                    {"name": "Content-Type",
                                     "value": "application/x-www-form-urlencoded"}],
                        "postData": {"mimeType": "application/x-www-form-urlencoded",
                                     "params": [{"name": "email", "value": "v@lab"}]}},
            "response": {"status": 200, "content": {"mimeType": "text/html"},
                         "headers": [{"name": "Set-Cookie",
                                      "value": f"sid={SECRET}; Path=/; SameSite=Strict"}]}}]}}
        path = self.root / "victim.har"
        path.write_text(json.dumps(har))
        import_har(self.ctx, path, "victim", role="user", workflow_state="settings")
        blob = (self.camp.state_dir / "recon.db").read_bytes()
        self.assertNotIn(SECRET.encode(), blob)
        self.led.sync()
        ctx = self.led.plan()["actions"][0]["contexts"][0]
        self.assertEqual((ctx["auth"], ctx["account"], ctx["workflow"]),
                         ("cookie", "victim", "settings"))
        self.assertEqual(ctx["token_channels"], ["header:x-csrf-token"])
        self.assertEqual(ctx["origins_seen"], ["https://acme.test"])
        self.assertEqual(ctx["cookies"][0]["samesite"], "strict")

    def test_openapi_declares_types_and_authority(self):
        spec = {"openapi": "3.0.1", "servers": [{"url": "https://acme.test/api"}],
                "components": {"securitySchemes": {
                    "session": {"type": "apiKey", "in": "cookie", "name": "sid"},
                    "token": {"type": "http", "scheme": "bearer"}}},
                "security": [{"session": []}],
                "paths": {
                    "/prefs": {"post": {"requestBody": {"content": {
                        "application/x-www-form-urlencoded": {"schema": {
                            "type": "object", "properties": {"theme": {"type": "string"}}}}}}}},
                    "/keys": {"delete": {"security": [{"token": []}]}}}}
        path = self.root / "spec.json"
        path.write_text(json.dumps(spec))
        import_openapi(self.ctx, path)
        prefs = self.ctx.store.find_asset("endpoint", "https://acme.test/api/prefs")
        self.assertEqual(prefs["attrs"]["spec_fields"][0]["location"], "form")
        self.led.sync()
        by_route = {a["route"]: a["contexts"][0] for a in self.led.plan()["actions"]}
        self.assertEqual((by_route["/api/prefs"]["auth"], by_route["/api/prefs"]["content_type"]),
                         ("cookie", "application/x-www-form-urlencoded"))
        self.assertEqual(by_route["/api/keys"]["auth"], "header")


class SkillReferenceTests(unittest.TestCase):
    def test_case_reference_matches_engine(self):
        text = (REPO / ".claude/skills/hunt-csrf/references/cases.md").read_text()
        self.assertEqual(len(CASES), 15)
        for case in CASES:
            self.assertIn(f"## `{case['id']}`", text)
            for variant, _, technique in case["variants"]:
                self.assertIn(f"| `{variant}` |", text)
                self.assertIn(technique, text)

    def test_skill_routes_and_provenance(self):
        skill = (REPO / ".claude/skills/hunt-csrf/SKILL.md").read_text()
        for case in CASES:
            self.assertIn(f"`{case['id']}`", skill)
        for needle in ("python3 -m recon csrf sync", "python3 -m recon csrf plan",
                       "python3 -m recon csrf record", "python3 -m recon csrf status",
                       "dedicated browser through Burp", "test accounts", "--prerequisite"):
            self.assertIn(needle, skill)
        sources = (REPO / ".claude/skills/hunt-csrf/references/sources.md").read_text()
        for needle in ("9d61d9142c350c1f6188ffb3c5e6e34407cf8438",
                       "0accf5fdc71ec7f03273aebb99268a8609f8dfd4",
                       "2f224f4c364183f67442e2bc6c07660adff0e481dd038c135f077a50f5c7d660",
                       "CC BY-NC 4.0", "Copyright (c) 2026 MindflareX"):
            self.assertIn(needle, sources)
        self.assertNotRegex(skill, r"(?i)^#+ .*(hard limits|when to stop|limitations)")


if __name__ == "__main__":
    unittest.main()
