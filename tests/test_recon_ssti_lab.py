"""Owned 127.0.0.1 HTTP lab for the inert SSTI detection subset.

The fixture is intentionally tiny: two arithmetic-only renderers, literal
reflection and a stored notification. It never evaluates Python code or sends
traffic outside loopback. It does not model sandbox escape or execution.
"""
import contextlib
import html
import http.client
import http.server
from pathlib import Path
import re
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.fields import FieldLedger
from recon.pipeline import Recon
from recon.ssti import SstiLedger
from tests.test_recon import write_campaign


def arithmetic_only(text, kind):
    """A whitelist grammar, not eval: unsigned decimal multiplication only."""
    syntax = {"braces": r"\{\{(\d{1,4})\*(\d{1,4})\}\}",
              "dollar": r"\$\{(\d{1,4})\*(\d{1,4})\}"}[kind]
    return re.sub(syntax, lambda m: str(int(m[1]) * int(m[2])), text)


def lab_request(url, method="GET", body=b""):
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1":
        raise AssertionError("owned loopback only")
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=2)
    try:
        conn.request(method, parts.path, body=body,
                     headers={"Content-Type": "text/plain"} if body else {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read(10000)
    finally:
        conn.close()


class OwnedSstiLab(unittest.TestCase):
    def test_reflected_literal_and_delayed_email_surfaces(self):
        class Renderer(http.server.BaseHTTPRequestHandler):
            stored = ""

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 256 or self.path not in ("/render", "/literal", "/store", "/export"):
                    self.send_error(400)
                    return
                raw = self.rfile.read(length).decode("ascii", "strict")
                if self.path == "/store":
                    type(self).stored = raw
                    data, status = b"queued", 202
                elif self.path == "/literal":
                    data, status = html.escape(raw).encode(), 200
                elif self.path == "/export":
                    data, status = ("field,value\npreview," + arithmetic_only(raw, "dollar")).encode(), 200
                else:
                    data, status = arithmetic_only(raw, "braces").encode(), 200
                self.send_response(status)
                self.send_header("Content-Type", "text/csv" if self.path == "/export" else "text/plain")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path != "/mail" or not type(self).stored:
                    self.send_error(404)
                    return
                data = ("Subject: owned notification\r\n\r\n" +
                        arithmetic_only(type(self).stored, "braces")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "message/rfc822")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        with contextlib.ExitStack() as stack, tempfile.TemporaryDirectory() as directory:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Renderer)
            stack.callback(server.server_close)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stack.callback(thread.join, 2)
            stack.callback(server.shutdown)
            origin = "http://127.0.0.1:" + str(server.server_address[1])
            camp = write_campaign(Path(directory) / "camp", "active", [],
                                  in_scope=["127.0.0.1"])
            ctx = Recon(camp, log=lambda _: None)
            stack.callback(ctx.store.close)
            ledger = SstiLedger(ctx)

            def make_set(path):
                asset = ctx.add_endpoint(origin + path, "har", method="POST", params=["template"])
                ctx.store.add_observation(asset, "POST", "owned-test",
                                          {"body": ["template"], "query": []}, 200, "lab")
                FieldLedger(ctx).sync(asset)
                return ledger.start(asset, "template", "POST", "form", "owned-test")

            def submit(path, probe):
                status, headers, body = lab_request(origin + path, "POST", probe["raw"].encode())
                rid = ctx.store.record_request("POST", origin + path, status, "owned-loopback",
                                               ["Content-Type"], headers, body=body,
                                               body_complete=True, basis="owned-loopback",
                                               req_body=probe["raw"].encode())
                return rid

            reflected = make_set("/render")
            reflected_surface = reflected["surfaces"][0]["id"]
            for probe in reflected["probes"]:
                if probe["family"] == "braces":
                    result = ledger.trace(reflected_surface, probe["id"],
                                          response_id=submit("/render", probe))
                    self.assertEqual(result["outcome"],
                                     "control" if probe["variant"] == "control" else "evaluated")
            self.assertEqual(ledger.status(reflected["set_id"])["surfaces"][0]["confirmed_families"],
                             ["braces"])

            literal = make_set("/literal")
            literal_surface = literal["surfaces"][0]["id"]
            for probe in literal["probes"]:
                result = ledger.trace(literal_surface, probe["id"],
                                      response_id=submit("/literal", probe))
                self.assertEqual(result["outcome"],
                                 "control" if probe["variant"] == "control" else "literal")
            self.assertTrue(ledger.status(literal["set_id"])["surfaces"][0]["negative"])

            export = make_set("/export")
            export_surface = ledger.add_surface(export["set_id"], "export", "owned CSV report")
            for probe in export["probes"]:
                if probe["family"] == "dollar":
                    ledger.trace(export_surface["id"], probe["id"],
                                 response_id=submit("/export", probe))
            export_rows = ledger.status(export["set_id"])["surfaces"]
            self.assertEqual(export_rows[0]["confirmed_families"], [])
            self.assertEqual(export_rows[1]["confirmed_families"], ["dollar"])

            stored = make_set("/store")
            mail = ledger.add_surface(stored["set_id"], "email", "owned test notification")
            for probe in stored["probes"]:
                if probe["family"] != "braces":
                    continue
                submit("/store", probe)
                status, headers, body = lab_request(origin + "/mail")
                rid = ctx.store.record_request("GET", origin + "/mail", status, "owned-loopback",
                                               [], headers, body=body, body_complete=True,
                                               basis="owned-loopback")
                ledger.trace(mail["id"], probe["id"], response_id=rid)
            summary = ledger.status(stored["set_id"])["surfaces"]
            self.assertEqual(summary[0]["confirmed_families"], [])  # 202 is not a render
            self.assertEqual(summary[1]["confirmed_families"], ["braces"])
            self.assertFalse(ledger.record(mail["id"], "stored", "observed",
                                           "Loopback notification with distinct controls")["finding_promoted"])
            self.assertTrue(ledger.verify()["verified"])


if __name__ == "__main__":
    unittest.main()
