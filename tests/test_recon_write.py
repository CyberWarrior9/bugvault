"""Scoped write-method executor: granted methods, payload evidence, scope/redirect gates."""
import http.server
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.campaign import Campaign, ConfigError, OutOfScope, PolicyViolation
from recon.net import FetchError, ScopedClient
from recon.pipeline import Recon
from recon.store import Store
from tests.test_recon import write_campaign


class EchoServer:
    """Owned loopback server that answers any method with an echo of what it received."""

    def __init__(self):
        lab = self
        self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                lab.seen.append({"method": self.command, "path": self.path,
                                 "body": body, "type": self.headers.get("Content-Type", "")})
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/echo")
                    self.end_headers()
                    return
                payload = json.dumps({"echo": body.decode("utf-8", "replace"),
                                      "method": self.command,
                                      "path": self.path}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _handle

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def write_write_campaign(root: Path, methods, mode="active"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "scope.json").write_text(json.dumps({
        "program": "lab", "seeds": [], "in_scope": ["127.0.0.1"], "out_of_scope": ["/logout"],
        "policy": {"mode": mode, "max_rps": 50, "user_agent": "bugvault-test",
                   "allowed_methods": methods}}))
    return Campaign.load(root)


class WriteMethodPolicyTests(unittest.TestCase):
    def test_default_is_read_only(self):
        with tempfile.TemporaryDirectory() as d:
            camp = write_write_campaign(Path(d) / "c", ["GET", "HEAD"])
            self.assertEqual(camp.policy.allowed_methods, ["GET", "HEAD"])

    def test_bad_method_lists_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for i, bad in enumerate(([], ["GET", "GET"], ["GET", "TRACE"], ["POST"],
                                     ["GET", "FETCH"])):
                with self.assertRaises(ConfigError, msg=repr(bad)):
                    write_write_campaign(Path(d) / f"c{i}", bad)

    def test_write_methods_require_active_mode(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ConfigError):
                write_write_campaign(Path(d) / "c", ["GET", "HEAD", "POST"], mode="passive")


class WriteMethodClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _ctx(self, methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")):
        camp = write_write_campaign(self.root / "camp", list(methods))
        ctx = Recon(camp, log=lambda _: None)
        self.addCleanup(ctx.store.close)
        return ctx

    def test_ungranted_method_is_refused(self):
        ctx = self._ctx(methods=("GET", "HEAD"))
        with EchoServer() as lab:
            with self.assertRaises(PolicyViolation):
                ctx.client.request("POST", f"http://127.0.0.1:{lab.port}/echo", "test",
                                   body=b"{}")
            self.assertEqual(lab.seen, [])
            self.assertEqual(ctx.store.request_count(), 0)

    def test_post_json_sends_body_and_records_payload_evidence(self):
        ctx = self._ctx()
        with EchoServer() as lab:
            resp = ctx.client.post_json(f"http://127.0.0.1:{lab.port}/echo",
                                        {"q": "canary_sqli_a1b2c3d4"}, "sqli-probe")
            self.assertEqual(resp.status, 200)
            self.assertEqual(lab.seen[0]["method"], "POST")
            self.assertIn("canary_sqli_a1b2c3d4", lab.seen[0]["body"].decode())
            self.assertEqual(lab.seen[0]["type"], "application/json")
            # payload evidence: stored body hash matches the exact bytes sent
            payload = ctx.store.request_payload(resp.request_id)
            self.assertEqual(payload["body_len"], len(lab.seen[0]["body"]))
            self.assertEqual(payload["content_type"], "application/json")
            import hashlib
            self.assertEqual(payload["body_sha256"],
                             hashlib.sha256(lab.seen[0]["body"]).hexdigest())
            stored = ctx.store.response(resp.request_id)
            self.assertEqual(stored["payload_sha256"], payload["body_sha256"])

    def test_post_form_and_explicit_content_type(self):
        ctx = self._ctx()
        with EchoServer() as lab:
            resp = ctx.client.post_form(f"http://127.0.0.1:{lab.port}/echo",
                                        {"a": "1", "b": "x y"}, "form-probe")
            self.assertEqual(lab.seen[0]["type"], "application/x-www-form-urlencoded")
            self.assertEqual(lab.seen[0]["body"], b"a=1&b=x+y")
            ctx.client.request("PUT", f"http://127.0.0.1:{lab.port}/echo", "put-probe",
                               body=b"<xml>xxe</xml>", content_type="text/xml")
            self.assertEqual(lab.seen[1]["method"], "PUT")
            self.assertEqual(lab.seen[1]["type"], "text/xml")

    def test_write_requests_do_not_follow_redirects(self):
        ctx = self._ctx()
        with EchoServer() as lab:
            resp = ctx.client.post_json(f"http://127.0.0.1:{lab.port}/redirect",
                                        {"x": 1}, "redirect-probe")
            self.assertEqual(resp.status, 302)
            self.assertEqual(resp.redirect_chain, [f"http://127.0.0.1:{lab.port}/redirect"])
            self.assertEqual(len(lab.seen), 1)  # the payload was sent exactly once

    def test_scope_still_enforced_for_write_methods(self):
        ctx = self._ctx()
        with EchoServer() as lab:
            with self.assertRaises(OutOfScope):
                ctx.client.post_json("https://evil.example.invalid/api", {"x": 1}, "oos")
            # excluded path is out of scope too
            with self.assertRaises(OutOfScope):
                ctx.client.post_json(f"http://127.0.0.1:{lab.port}/logout", {"x": 1}, "excluded")
            self.assertEqual(lab.seen, [])

    def test_request_body_size_limit(self):
        ctx = self._ctx()
        with EchoServer() as lab:
            with self.assertRaises(PolicyViolation):
                ctx.client.request("POST", f"http://127.0.0.1:{lab.port}/echo", "big",
                                   body=b"x" * (ctx.policy.max_body_bytes + 1))
            self.assertEqual(lab.seen, [])

    def test_get_cannot_carry_a_body(self):
        ctx = self._ctx()
        with EchoServer() as lab:
            with self.assertRaises(PolicyViolation):
                ctx.client.request("GET", f"http://127.0.0.1:{lab.port}/echo", "bad",
                                   body=b"{}")

    def test_host_header_override_still_refused(self):
        ctx = self._ctx()
        with EchoServer() as lab:
            with self.assertRaises(PolicyViolation):
                ctx.client.request("POST", f"http://127.0.0.1:{lab.port}/echo", "hdr",
                                   body=b"{}", headers={"Host": "evil.example"})

    def test_budget_and_rate_still_apply_to_writes(self):
        ctx = self._ctx()
        ctx.client.budget.remaining = 1
        with EchoServer() as lab:
            ctx.client.post_json(f"http://127.0.0.1:{lab.port}/echo", {"a": 1}, "one")
            with self.assertRaises(Exception) as raised:
                ctx.client.post_json(f"http://127.0.0.1:{lab.port}/echo", {"b": 2}, "two")
            self.assertIn("budget", str(raised.exception).lower())
            self.assertEqual(len(lab.seen), 1)

    def test_legacy_requests_keep_their_response_shape(self):
        ctx = self._ctx()
        with EchoServer() as lab:
            get_resp = ctx.client.get(f"http://127.0.0.1:{lab.port}/echo", "read")
            data = ctx.store.response(get_resp.request_id)
            self.assertNotIn("payload_sha256", data)
            self.assertIsNone(ctx.store.request_payload(get_resp.request_id))


if __name__ == "__main__":
    unittest.main()
