"""Owned loopback cloud-storage-shaped workflow, not provider/IAM certification."""
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest

from recon.campaign import Campaign
from recon.cloud import CloudLedger
from recon.pipeline import Recon


class StorageFixture:
    def __init__(self):
        fixture = self
        self.value = b"before owned object"
        self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def _respond(self, code, body):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                fixture.seen.append(("GET", self.path))
                if self.path == "/control":
                    self._respond(403, b"denied bvcloud_control_02b")
                elif self.path == "/canary" and fixture.value is not None:
                    self._respond(200, fixture.value)
                else:
                    self._respond(404, b"not found")

            def do_PUT(self):
                fixture.seen.append(("PUT", self.path))
                if self.path != "/canary":
                    self._respond(403, b"denied")
                    return
                size = int(self.headers.get("Content-Length", "0"))
                fixture.value = self.rfile.read(size)
                self._respond(200, b"write accepted " + fixture.value)

            def do_DELETE(self):
                fixture.seen.append(("DELETE", self.path))
                if self.path == "/canary":
                    fixture.value = None
                    self._respond(200, b"cleaned up owned object")
                else:
                    self._respond(403, b"denied")

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class CloudOwnedLabTests(unittest.TestCase):
    def test_owned_write_control_replay_cleanup_and_offline_receipt(self):
        with tempfile.TemporaryDirectory() as tmp, StorageFixture() as fixture:
            root = Path(tmp) / "camp"
            root.mkdir()
            config = {"program": "owned-local-fixture", "seeds": [],
                      "in_scope": ["127.0.0.1"], "out_of_scope": ["/logout"],
                      "program_url": "https://program.example/owned-fixture",
                      "rules": ["fixture only: owned canary GET/PUT/DELETE and cleanup"],
                      "cloud": {"rules_reviewed": "2026-11-16", "grants": ["write"], "budget": 10},
                      "policy": {"mode": "active", "max_rps": 50,
                                 "allowed_methods": ["GET", "HEAD", "PUT", "DELETE"]}}
            (root / "scope.json").write_text(json.dumps(config))
            (root / "refs.txt").write_text("s3://lab-bucket/canary")
            ctx = Recon(Campaign.load(root), log=lambda _: None)
            self.addCleanup(ctx.store.close)
            ledger = CloudLedger(ctx)
            ledger.import_text("refs.txt")
            ref = ledger.plan()["candidates"][0]["id"]
            base = f"http://127.0.0.1:{fixture.server.server_address[1]}"
            before = ctx.client.request("GET", base + "/canary", "owned-lab-before")
            self.assertEqual(before.status, 200)
            marker = b"bvcloud_owned_001a"
            write = ctx.client.request("PUT", base + "/canary", "owned-lab-write", body=marker)
            after = ctx.client.request("GET", base + "/canary", "owned-lab-after")
            replay = ctx.client.request("GET", base + "/canary", "owned-lab-replay")
            control = ctx.client.request("GET", base + "/control", "owned-lab-control")
            cleanup = ctx.client.request("DELETE", base + "/canary", "owned-lab-cleanup")
            restored = ctx.client.request("GET", base + "/canary", "owned-lab-verify")
            self.assertEqual([r.status for r in (write, after, replay, control, cleanup, restored)],
                             [200, 200, 200, 403, 200, 404])
            self.assertEqual(fixture.value, None)
            evidence = root / "evidence"
            evidence.mkdir()
            roles = {"owner-baseline": before.body, "before": before.body + b" / before",
                     "test": write.body, "after": after.body, "replay": b"fresh replay " + replay.body,
                     "negative-control": control.body, "cleanup": cleanup.body}
            for role, body in roles.items():
                (evidence / role).write_bytes(body)
            event = {"schema": 1, "reference": ref, "case": "CM-02", "state": "canary-proved",
                     "channel": "native", "grant": "write", "requests": 1, "request_ids": [write.request_id],
                     "operation": {"principal": "owned-local-fixture", "action": "storage:PutObject",
                                   "resource_id": "lab-bucket", "method": "PUT",
                                   "request_url": base + "/canary"},
                     "marker": marker.decode(), "control_marker": "bvcloud_control_02b",
                     "artifacts": {role: "evidence/" + role for role in roles},
                     "content_assessment": {"content_class": "synthetic",
                                            "intended_publicness": "private",
                                            "confidence": "controlled"}}
            receipt = ledger.record(event)
            self.assertFalse(receipt["finding_promoted"])
            self.assertTrue(ledger.verify()["ok"])
            self.assertEqual(ctx.store.network_attempts(), 7)
            self.assertEqual(fixture.seen[0], ("GET", "/canary"))


if __name__ == "__main__":
    unittest.main()
