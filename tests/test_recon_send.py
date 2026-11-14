"""`recon send`: the skills' executor goes through the scoped client and stores evidence."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.campaign import Campaign
from recon.cli import main
from recon.factcheck import ResponseFacts
from recon.pipeline import Recon
from recon.store import Store
from tests.test_recon_write import EchoServer, write_write_campaign


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class InitMethodTests(unittest.TestCase):
    def test_defaults_stay_read_only_in_every_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in ("passive", "active", "loud"):
                with self.subTest(mode=mode):
                    root = Path(directory) / mode
                    code, _, err = run_cli(["init", str(root), "--seed", "acme.test", "--mode", mode])
                    self.assertEqual(code, 0, err)
                    self.assertEqual(Campaign.load(root).policy.allowed_methods, ["GET", "HEAD"])

    def test_explicit_full_grant_is_persisted_and_rendered(self):
        from recon.brief import render
        methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "camp"
            argv = ["init", str(root), "--seed", "acme.test", "--mode", "active"]
            for method in methods[2:] + ["put"]:  # normalize and deduplicate extra grants
                argv += ["--allow-method", method]
            code, _, err = run_cli(argv)
            self.assertEqual(code, 0, err)
            camp = Campaign.load(root)
            self.assertEqual(camp.policy.allowed_methods, methods)
            self.assertIn(", ".join(methods), render(camp, "hunter"))
            self.assertFalse(camp.state_dir.exists(), "init must not execute any target requests")

    def test_passive_extra_methods_fail_before_creating_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            for method in ("POST", "PUT", "PATCH", "OPTIONS", "DELETE"):
                with self.subTest(method=method):
                    root = Path(directory) / method
                    code, _, err = run_cli(["init", str(root), "--seed", "acme.test",
                                            "--allow-method", method])
                    self.assertEqual(code, 1)
                    self.assertIn("active or loud", err)
                    self.assertFalse(root.exists())

    def test_existing_scope_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "camp"
            argv = ["init", str(root), "--seed", "acme.test", "--mode", "active"]
            self.assertEqual(run_cli(argv)[0], 0)
            before = (root / "scope.json").read_bytes()
            self.assertEqual(run_cli(argv + ["--allow-method", "DELETE"])[0], 1)
            self.assertEqual((root / "scope.json").read_bytes(), before)

    def test_unsupported_method_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "camp"
            with self.assertRaises(SystemExit) as raised:
                run_cli(["init", str(root), "--seed", "acme.test", "--mode", "active",
                         "--allow-method", "TRACE"])
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(root.exists())


class SendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.lab = EchoServer()
        self.lab.__enter__()
        self.addCleanup(self.lab.__exit__)
        self.base = f"http://127.0.0.1:{self.lab.port}"

    def campaign(self, methods=("GET", "HEAD", "POST"), mode="active", rps=None):
        camp = write_write_campaign(self.root / "camp", list(methods), mode=mode)
        if rps is not None:
            raw = json.loads((camp.root / "scope.json").read_text())
            raw["policy"]["max_rps"] = rps
            (camp.root / "scope.json").write_text(json.dumps(raw))
        return str(camp.root)

    def test_get_prints_request_id_that_fact_check_can_verify(self):
        camp = self.campaign()
        code, out, err = run_cli(["send", camp, self.base + "/echo"])
        self.assertEqual(code, 0, err)
        result = json.loads(out)
        self.assertEqual((result["status"], self.lab.seen[0]["method"]), (200, "GET"))
        self.assertIn("fact check", err)
        ctx = Recon(Campaign.load(Path(camp)), log=lambda _: None)
        try:
            fact = ResponseFacts(ctx).add(result["request_id"], {"type": "status_is", "expected": 200})
            self.assertEqual(fact["outcome"], "supported")
        finally:
            ctx.store.close()

    def test_post_requires_the_method_grant(self):
        camp = self.campaign(methods=("GET", "HEAD"))
        code, _, err = run_cli(["send", camp, self.base + "/login", "--method", "POST", "--json", "{}"])
        self.assertEqual(code, 1)
        self.assertIn("allowed_methods", err)
        self.assertEqual(self.lab.seen, [])

    def test_put_options_delete_send_and_store_the_actual_method(self):
        camp = self.campaign(methods=("GET", "HEAD", "PUT", "OPTIONS", "DELETE"))
        store = Store(Path(camp) / ".recon" / "recon.db")
        try:
            for method in ("PUT", "OPTIONS", "DELETE"):
                with self.subTest(method=method):
                    extra = ["--json", '{"marker":"owned-test-resource"}'] if method == "PUT" else []
                    code, out, err = run_cli(["send", camp, self.base + "/echo", "--method", method] + extra)
                    self.assertEqual(code, 0, err)
                    result = json.loads(out)
                    self.assertEqual((result["method"], result["status"]), (method, 200))
                    self.assertEqual(self.lab.seen[-1]["method"], method)
                    self.assertEqual(store.response(result["request_id"])["method"], method)
                    payload = store.request_payload(result["request_id"])
                    if self.lab.seen[-1]["body"]:
                        self.assertEqual(payload["body_len"], len(self.lab.seen[-1]["body"]))
                    else:
                        self.assertIsNone(payload)  # no payload artifact for a bodyless request
        finally:
            store.close()

    def test_put_options_delete_require_individual_grants(self):
        camp = self.campaign()
        for method in ("PUT", "OPTIONS", "DELETE"):
            with self.subTest(method=method):
                code, _, err = run_cli(["send", camp, self.base + "/echo", "--method", method])
                self.assertEqual(code, 1)
                self.assertIn("allowed_methods", err)
        self.assertEqual(self.lab.seen, [])

    def test_put_options_delete_still_obey_scope(self):
        camp = self.campaign(methods=("GET", "HEAD", "PUT", "OPTIONS", "DELETE"))
        for method in ("PUT", "OPTIONS", "DELETE"):
            for url in (self.base + "/logout", "https://outside.example.invalid/echo"):
                with self.subTest(method=method, url=url):
                    code, _, _ = run_cli(["send", camp, url, "--method", method])
                    self.assertEqual(code, 1)
        self.assertEqual(self.lab.seen, [])

    def test_put_options_delete_never_auto_follow_redirects(self):
        camp = self.campaign(methods=("GET", "HEAD", "PUT", "OPTIONS", "DELETE"))
        for method in ("PUT", "OPTIONS", "DELETE"):
            with self.subTest(method=method):
                before = len(self.lab.seen)
                code, out, err = run_cli(["send", camp, self.base + "/redirect", "--method", method])
                self.assertEqual(code, 0, err)
                self.assertEqual(json.loads(out)["status"], 302)
                self.assertEqual(len(self.lab.seen), before + 1)
                self.assertEqual(self.lab.seen[-1]["path"], "/redirect")

    def test_json_and_form_bodies_are_sent_and_stored(self):
        camp = self.campaign()
        code, out, err = run_cli(["send", camp, self.base + "/login", "--method", "POST",
                                  "--json", '{"otp":"900001"}'])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.lab.seen[0]["type"], "application/json")
        self.assertEqual(self.lab.seen[0]["body"], b'{"otp":"900001"}')
        request_id = json.loads(out)["request_id"]
        code, _, err = run_cli(["send", camp, self.base + "/saml/acs", "--method", "POST",
                                "--form", "SAMLResponse=a+b/c=", "--form", "RelayState=x"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.lab.seen[1]["type"], "application/x-www-form-urlencoded")
        self.assertEqual(self.lab.seen[1]["body"], b"SAMLResponse=a%2Bb%2Fc%3D&RelayState=x")
        store = Store(Path(camp) / ".recon" / "recon.db")
        try:
            self.assertEqual(store.request_payload(request_id)["body_len"], len(b'{"otp":"900001"}'))
        finally:
            store.close()

    def test_headers_are_sent_but_host_overrides_are_refused(self):
        camp = self.campaign()
        code, _, err = run_cli(["send", camp, self.base + "/echo", "--header", "X-Authenticated: true"])
        self.assertEqual(code, 0, err)
        code, _, err = run_cli(["send", camp, self.base + "/echo", "--header", "Host: evil.example"])
        self.assertEqual(code, 1)
        code, _, err = run_cli(["send", camp, self.base + "/echo", "--header", "no-colon"])
        self.assertEqual(code, 1)
        self.assertEqual(len(self.lab.seen), 1)

    def test_scope_mode_and_body_rules_are_enforced_before_sending(self):
        camp = self.campaign()
        cases = [
            ["send", camp, "https://outside.example.invalid/login"],
            ["send", camp, self.base + "/logout"],
            ["send", camp, self.base + "/echo", "--data", "x"],
            ["send", camp, self.base + "/echo", "--method", "POST", "--json", "{bad"],
            ["send", camp, self.base + "/echo", "--method", "POST", "--json", "{}", "--data", "x"],
            ["send", camp, self.base + "/echo", "--purpose", ""],
        ]
        for argv in cases:
            with self.subTest(argv=argv[2:]):
                code, _, _ = run_cli(argv)
                self.assertEqual(code, 1)
        passive = self.campaign(methods=("GET", "HEAD"), mode="passive")
        self.assertEqual(run_cli(["send", passive, self.base + "/echo"])[0], 1)
        self.assertEqual(self.lab.seen, [])

    def test_no_follow_returns_the_redirect(self):
        camp = self.campaign()
        code, out, _ = run_cli(["send", camp, self.base + "/redirect", "--no-follow"])
        self.assertEqual((code, json.loads(out)["status"]), (0, 302))
        code, out, _ = run_cli(["send", camp, self.base + "/redirect"])
        self.assertEqual((code, json.loads(out)["status"]), (0, 200))

    def test_separate_invocations_share_the_campaign_rate_limit(self):
        camp = self.campaign(rps=2)  # one request per 0.5 s per host
        started = time.monotonic()
        for _ in range(3):
            self.assertEqual(run_cli(["send", camp, self.base + "/echo"])[0], 0)
        # Each invocation builds a fresh client; only the persistent pacing spaces them.
        self.assertGreaterEqual(time.monotonic() - started, 0.9)


class PacingTests(unittest.TestCase):
    def test_slots_are_shared_between_store_instances_and_capped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recon.db"
            first, second = Store(path), Store(path)
            try:
                self.assertEqual(first.reserve_pacing_slot("acme.test", 0.5), 0.0)
                self.assertGreater(second.reserve_pacing_slot("acme.test", 0.5), 0.3)
                self.assertEqual(second.reserve_pacing_slot("other.test", 0.5), 0.0)
                first.db.execute("UPDATE host_pacing SET next_at=? WHERE host='acme.test'",
                                 (time.time() + 3600,))
                first.db.commit()
                self.assertLessEqual(first.reserve_pacing_slot("acme.test", 0.5), 0.5)
            finally:
                first.close()
                second.close()


if __name__ == "__main__":
    unittest.main()
