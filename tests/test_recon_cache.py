"""Offline cache-ledger gates: channels, budget, markers, integrity, staleness, CLI.

No CDN, no shared cache and no third-party service is contacted; the tiny loopback
origin only exists so events can bind genuine stored scoped responses.
"""
import contextlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import urlsplit

from recon.cache import CacheLedger
from recon.campaign import Campaign
from recon.cli import main
from recon.pipeline import Recon

CONTROL = "bvcache_control_02b"


class _Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/public.css":
            body = b"public asset; owner-canary=" + CONTROL.encode()
            self.send_response(200)
            self.send_header("Cache-Control", "public, max-age=60")
        elif path == "/account/settings":
            body = b"private account settings"
            self.send_response(200)
            self.send_header("Cache-Control", "private, no-store")
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def write_campaign(root, budget):
    root.mkdir(parents=True)
    config = {"program": "owned-local-cache-fixture", "seeds": [],
              "in_scope": ["127.0.0.1"], "out_of_scope": ["/logout"],
              "program_url": "https://program.example/owned-cache-fixture",
              "rules": ["fixture only: owned loopback cache evidence"],
              "cache": {"rules_reviewed": "2026-11-20", "grants": ["write"], "budget": budget},
              "policy": {"mode": "active", "max_rps": 50,
                         "allowed_methods": ["GET", "HEAD"]}}
    (root / "scope.json").write_text(json.dumps(config))


class CacheLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        write_campaign(self.root, budget=20)
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.ctx = None

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        if self.ctx is not None:
            self.ctx.store.close()

    def _ledger(self):
        self.ctx = Recon(Campaign.load(self.root), log=lambda _: None)
        return CacheLedger(self.ctx)

    def _get(self, path):
        return self.ctx.client.request("GET", self.base + path, "cache-test")

    def _event(self, reference, path="/public.css", **changes):
        base = {"schema": 1, "reference": reference, "case": "CP-01",
                "state": "observed", "channel": "native", "grant": "write",
                "requests": 1, "request_ids": [reference],
                "operation": {"principal": "owned-a", "action": "cache:observe",
                              "resource_id": path, "method": "GET",
                              "request_url": self.base + path,
                              "variant": "baseline"},
                "content_assessment": {"content_class": "public-asset",
                                       "intended_publicness": "public-intended",
                                       "confidence": "controlled"},
                "reason": "owned baseline observation"}
        return {**base, **changes}

    def _cli(self, *argv):
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return main(list(argv))

    def test_record_deduplicates_and_cli_roundtrip(self):
        ledger = self._ledger()
        response = self._get("/public.css")
        event = self._event(response.request_id)
        (self.root / "evidence").mkdir()
        (self.root / "evidence" / "event.json").write_text(json.dumps(event))
        self.assertEqual(self._cli("cache", "record", str(self.root),
                                   "--file", "evidence/event.json"), 0)
        again = ledger.record(event)
        self.assertTrue(again["deduplicated"])
        self.assertEqual(again["event"], ledger.status()["top"][0]["id"])
        shown = ledger.show(response.request_id)
        self.assertEqual(len(shown["events"]), 1)
        self.assertEqual(shown["reference"]["path"], "/public.css")
        self.assertFalse(shown["finding_promoted"])
        self.assertEqual(self._cli("cache", "show", str(self.root),
                                   "--reference", str(response.request_id)), 0)
        self.assertEqual(self._cli("cache", "status", str(self.root)), 0)
        self.assertEqual(self._cli("cache", "verify", str(self.root)), 0)

    def test_verify_flags_artifact_tampering(self):
        ledger = self._ledger()
        response = self._get("/public.css")
        artifact = self.root / "evidence" / "audit.bin"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"edge log line 1\n")
        ledger.record(self._event(response.request_id,
                                  artifacts={"audit": "evidence/audit.bin"}))
        self.assertTrue(ledger.verify()["ok"])
        artifact.write_bytes(b"edge log line 1\nedge log line 2 tampered\n")
        report = ledger.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any(issue.get("role") == "audit" for issue in report["issues"]))
        self.assertEqual(self._cli("cache", "verify", str(self.root)), 2)

    def test_shared_declared_budget_is_enforced(self):
        config = json.loads((self.root / "scope.json").read_text())
        config["cache"]["budget"] = 1
        (self.root / "scope.json").write_text(json.dumps(config))
        ledger = self._ledger()
        first = self._get("/public.css")
        second = self._get("/account/settings")
        ledger.record(self._event(first.request_id))
        with self.assertRaisesRegex(ValueError, "budget"):
            ledger.record(self._event(second.request_id, path="/account/settings"))

    def test_channel_marker_and_reference_gates(self):
        ledger = self._ledger()
        response = self._get("/public.css")
        with self.assertRaisesRegex(ValueError, "offline/owned-lab"):
            ledger.record(self._event(response.request_id, channel="offline", requests=1,
                                      request_ids=[]))
        with self.assertRaisesRegex(ValueError, "Burp events"):
            ledger.record(self._event(response.request_id, channel="burp"))
        with self.assertRaisesRegex(ValueError, "markers are reserved"):
            ledger.record(self._event(response.request_id, marker="bvcache_x_001a"))
        with self.assertRaisesRegex(ValueError, "blocked event"):
            ledger.record(self._event(response.request_id, state="blocked", requests=1))
        with self.assertRaisesRegex(ValueError, "no stored scoped response"):
            ledger.record(self._event(999))

    def test_policy_change_marks_recorded_events_stale(self):
        ledger = self._ledger()
        response = self._get("/public.css")
        ledger.record(self._event(response.request_id))
        self.ctx.store.close()
        config = json.loads((self.root / "scope.json").read_text())
        config["rules"] = list(config["rules"]) + ["revised fixture rule 2026-11-21"]
        (self.root / "scope.json").write_text(json.dumps(config))
        self.ctx = None
        reopened = self._ledger()
        report = reopened.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("stale" in issue["reason"] for issue in report["issues"]))

    def test_incomplete_viewer_cannot_be_recorded_as_proof(self):
        ledger = self._ledger()
        rid = self.ctx.store.record_request("GET", self.base + "/public.css", 200,
                                             "offline-incomplete-fixture", [], {}, b"partial",
                                             body_complete=False, basis="owned-lab")
        with self.assertRaisesRegex(ValueError, "complete captured viewer body"):
            ledger.record(self._event(rid, state="canary-proved", channel="offline",
                                      requests=0, request_ids=[]))


if __name__ == "__main__":
    unittest.main()
