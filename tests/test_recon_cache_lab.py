"""Owned loopback cache-edge workflow, not CDN/vendor cache certification.

Two tiny 127.0.0.1 servers model a configurable edge and a private origin.
The fixtures prove the ledger distinguishes a real store/serve contrast from a
keyed/no-store negative control; they do not establish any third-party cache.
"""
import http.client
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import parse_qsl, unquote, urlsplit

from recon.cache import CacheLedger
from recon.campaign import Campaign, ConfigError
from recon.pipeline import Recon

CONTROL = b"bvcache_control_02b"


class CacheFixture:
    """Edge key behavior is configurable so the same lab can emit both controls."""

    def __init__(self):
        fixture = self
        self.fixed_key = False       # True: attack query is part of the cache key
        self.viewer_keyed = False    # True: X-Viewer is part of the cache key
        self.respect_private = False
        self.normalize_key = False
        self.cache = {}
        self.origin_seen = []

        class Origin(http.server.BaseHTTPRequestHandler):
            def _respond(self, code, body, headers):
                self.send_response(code)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parts = urlsplit(self.path)
                query = dict(parse_qsl(parts.query, keep_blank_values=True))
                viewer = self.headers.get("X-Viewer", "anonymous")
                fixture.origin_seen.append((viewer, parts.path))
                if parts.path == "/account/settings":
                    body = b"private account settings; owner-canary=" + CONTROL
                    if "bvcache" in query:
                        body += b"; poison=" + query["bvcache"].encode()
                    self._respond(200, body, {"Cache-Control": "public, max-age=60"})
                elif parts.path == "/account/settings/profile.css":
                    if viewer != "owner":
                        self._respond(403, b"denied; owner-canary=" + CONTROL,
                                      {"Cache-Control": "no-store"})
                    else:
                        self._respond(200, b"private profile; owner=bvdeceive_owner_001a; "
                                           b"owner-canary=" + CONTROL,
                                      {"Cache-Control": "private, max-age=60"})
                elif parts.path == "/public.css":
                    self._respond(200, b"public asset; owner-canary=" + CONTROL,
                                  {"Cache-Control": "public, max-age=60"})
                elif parts.path in ("/variant/a%2Fb", "/variant/a/b"):
                    body = b"encoded synthetic variant" if "%2F" in parts.path else b"literal synthetic variant"
                    self._respond(200, body, {"Cache-Control": "public, max-age=60"})
                else:
                    self._respond(404, b"not found", {})

            def log_message(self, *args):
                pass

        class Edge(http.server.BaseHTTPRequestHandler):
            def _respond(self, code, body, headers):
                self.send_response(code)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parts = urlsplit(self.path)
                query = parse_qsl(parts.query, keep_blank_values=True)
                if fixture.fixed_key:
                    key_query = tuple(sorted(query))
                else:
                    key_query = tuple(sorted((k, v) for k, v in query if k != "bvcache"))
                viewer = self.headers.get("X-Viewer", "anonymous")
                key_path = unquote(parts.path) if fixture.normalize_key else parts.path
                key = (key_path, key_query, viewer if fixture.viewer_keyed else "")
                if key in fixture.cache:
                    status, headers, body = fixture.cache[key]
                    self._respond(status, body, {**headers, "X-Cache": "HIT"})
                    return
                connection = http.client.HTTPConnection(
                    "127.0.0.1", fixture.origin.server_address[1], timeout=5)
                connection.request("GET", self.path, headers={"X-Viewer": viewer})
                response = connection.getresponse()
                body = response.read()
                status = response.status
                headers = {name.lower(): value for name, value in response.getheaders()
                           if name.lower() in ("cache-control", "content-type")}
                connection.close()
                private = any(word in headers.get("cache-control", "").lower()
                              for word in ("private", "no-store"))
                if status == 200 and not (fixture.respect_private and private):
                    fixture.cache[key] = (status, headers, body)
                self._respond(status, body, {**headers, "X-Cache": "MISS"})

            def log_message(self, *args):
                pass

        self.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        self.edge = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Edge)
        self.threads = [threading.Thread(target=server.serve_forever, daemon=True)
                        for server in (self.origin, self.edge)]

    @property
    def base(self):
        return f"http://127.0.0.1:{self.edge.server_address[1]}"

    def __enter__(self):
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, *args):
        for server in (self.edge, self.origin):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join()


def write_campaign(root):
    root.mkdir(parents=True)
    config = {"program": "owned-local-cache-fixture", "seeds": [],
              "in_scope": ["127.0.0.1"], "out_of_scope": ["/logout"],
              "program_url": "https://program.example/owned-cache-fixture",
              "rules": ["fixture only: owned loopback cache edge/origin evidence"],
              "cache": {"rules_reviewed": "2026-11-20", "grants": ["write"], "budget": 20},
              "policy": {"mode": "active", "max_rps": 50,
                         "allowed_methods": ["GET", "HEAD"]}}
    (root / "scope.json").write_text(json.dumps(config))


class CacheOwnedLabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        write_campaign(self.root)
        self.ctx = Recon(Campaign.load(self.root), log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.ledger = CacheLedger(self.ctx)

    def fetch(self, fixture, path, purpose, viewer="anonymous"):
        return self.ctx.client.request("GET", fixture.base + path, purpose,
                                       headers={"X-Viewer": viewer})

    def artifact(self, role, data):
        path = self.root / "evidence" / role
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return "evidence/" + role

    def event(self, reference, request_ids, resource_id, marker, artifacts, **changes):
        base = {"schema": 1, "reference": reference, "case": "CP-01",
                "state": "canary-proved", "channel": "native", "grant": "write",
                "requests": len(request_ids), "request_ids": request_ids,
                "operation": {"principal": "owned-lab-b", "action": "cache:serve",
                              "resource_id": resource_id, "method": "GET",
                              "request_url": self.base_url + resource_id,
                              "variant": "owned-loopback"},
                "marker": marker, "control_marker": CONTROL.decode(),
                "artifacts": artifacts,
                "content_assessment": {"content_class": "private-content",
                                       "intended_publicness": "private",
                                       "confidence": "controlled"},
                "reason": "owned loopback edge distinguished store/serve from control"}
        return {**base, **changes}

    def test_poisoning_store_serve_negative_and_positive_controls(self):
        marker = "bvcache_poison_001a"
        with CacheFixture() as fixture:
            self.base_url = fixture.base
            baseline = self.fetch(fixture, "/account/settings", "cache-baseline")
            fixture.cache.clear()  # fresh controlled state after the pre-marker baseline
            prime = self.fetch(fixture, f"/account/settings?bvcache={marker}", "cache-prime")
            replay = self.fetch(fixture, f"/account/settings?bvcache={marker}", "cache-replay")
            cross = self.fetch(fixture, "/account/settings", "cache-cross-viewer")
            self.assertEqual([r.status for r in (baseline, prime, replay, cross)],
                             [200, 200, 200, 200])
            self.assertEqual([r.headers.get("x-cache") for r in (prime, replay, cross)],
                             ["MISS", "HIT", "HIT"])
            self.assertIn(marker.encode(), prime.body)
            self.assertIn(marker.encode(), replay.body)
            self.assertIn(marker.encode(), cross.body)
            self.assertNotIn(marker.encode(), baseline.body)
            fixture.fixed_key = True
            fixture.cache.clear()
            negative_prime = self.fetch(fixture, f"/account/settings?bvcache={marker}",
                                        "cache-negative-prime")
            negative_view = self.fetch(fixture, "/account/settings", "cache-negative-viewer")
            self.assertEqual(negative_prime.headers.get("x-cache"), "MISS")
            self.assertEqual(negative_view.headers.get("x-cache"), "MISS")
            self.assertNotIn(marker.encode(), negative_view.body)
            positive_prime = self.fetch(fixture, "/public.css", "cache-positive-prime")
            positive_hit = self.fetch(fixture, "/public.css", "cache-positive-hit")
            self.assertEqual(positive_prime.headers.get("x-cache"), "MISS")
            self.assertEqual(positive_hit.headers.get("x-cache"), "HIT")
            self.assertIn(CONTROL, positive_hit.body)
            self.assertNotIn(marker.encode(), positive_hit.body)
            self.assertIn(CONTROL, negative_view.body)
            roles = {
                "baseline": baseline.body,
                "test": b"prime-request\n" + prime.body,
                "replay": b"replay-request\n" + replay.body,
                "cross-viewer": cross.body,
                "negative-control": b"fixed-edge\n" + negative_view.body,
                "positive-control": positive_hit.body,
            }
            artifacts = {role: self.artifact(role, body) for role, body in roles.items()}
            ids = [r.request_id for r in (baseline, prime, replay, cross, negative_prime,
                                          negative_view, positive_prime, positive_hit)]
            event = self.event(cross.request_id, ids, "/account/settings", marker, artifacts)
            receipt = self.ledger.record(event)
            self.assertFalse(receipt["executed"])
            self.assertFalse(receipt["finding_promoted"])
            self.assertTrue(receipt["semantic_review_required"])
            self.assertTrue(self.ledger.verify()["ok"])
            self.assertEqual(self.ledger.status()["by_state"]["canary-proved"], 1)
            self.assertFalse(self.ledger.show(cross.request_id)["finding_promoted"])
            self.assertEqual(self.ctx.store.network_attempts(), 8)

    def test_deception_cross_viewer_private_body_and_fixed_control(self):
        marker = "bvdeceive_owner_001a"
        with CacheFixture() as fixture:
            self.base_url = fixture.base
            baseline = self.fetch(fixture, "/account/settings/profile.css", "deceive-baseline")
            fixture.cache.clear()
            prime = self.fetch(fixture, "/account/settings/profile.css", "deceive-owner-prime",
                               viewer="owner")
            replay = self.fetch(fixture, "/account/settings/profile.css", "deceive-owner-replay",
                                viewer="owner")
            cross = self.fetch(fixture, "/account/settings/profile.css", "deceive-cross-viewer")
            self.assertEqual([r.status for r in (baseline, prime, replay, cross)],
                             [403, 200, 200, 200])
            self.assertEqual([r.headers.get("x-cache") for r in (prime, replay, cross)],
                             ["MISS", "HIT", "HIT"])
            self.assertIn(marker.encode(), cross.body)
            self.assertNotIn(marker.encode(), baseline.body)
            fixture.viewer_keyed = True
            fixture.cache.clear()
            negative_prime = self.fetch(fixture, "/account/settings/profile.css",
                                        "deceive-negative-prime", viewer="owner")
            negative_view = self.fetch(fixture, "/account/settings/profile.css",
                                       "deceive-negative-viewer")
            self.assertEqual(negative_prime.status, 200)
            self.assertEqual(negative_view.status, 403)
            self.assertNotIn(marker.encode(), negative_view.body)
            positives = [self.fetch(fixture, "/public.css", "deceive-positive-prime"),
                         self.fetch(fixture, "/public.css", "deceive-positive-hit")]
            self.assertEqual(positives[1].headers.get("x-cache"), "HIT")
            self.assertIn(CONTROL, positives[1].body)
            self.assertNotIn(marker.encode(), positives[1].body)
            roles = {
                "baseline": baseline.body,
                "test": b"owner-prime\n" + prime.body,
                "replay": b"owner-replay\n" + replay.body,
                "cross-viewer": cross.body,
                "negative-control": b"fixed-viewer\n" + negative_view.body,
                "positive-control": positives[1].body,
            }
            artifacts = {role: self.artifact(role, body) for role, body in roles.items()}
            ids = [r.request_id for r in (baseline, prime, replay, cross, negative_prime,
                                          negative_view, *positives)]
            event = self.event(cross.request_id, ids, "/account/settings/profile.css", marker,
                               artifacts, case="CD-01",
                               operation={"principal": "anonymous", "action": "cache:deceive",
                                          "resource_id": "/account/settings/profile.css",
                                          "method": "GET",
                                          "request_url": fixture.base
                                          + "/account/settings/profile.css",
                                          "variant": "static-looking-private-route"},
                               content_assessment={"content_class": "authenticated-content",
                                                   "intended_publicness": "private",
                                                   "confidence": "controlled"})
            receipt = self.ledger.record(event)
            self.assertFalse(receipt["finding_promoted"])
            self.assertTrue(self.ledger.verify()["ok"])
            self.assertEqual(self.ctx.store.network_attempts(), 8)

    def test_proof_without_negative_or_positive_control_is_rejected(self):
        marker = "bvcache_poison_001a"
        with CacheFixture() as fixture:
            self.base_url = fixture.base
            baseline = self.fetch(fixture, "/account/settings", "proof-baseline")
            fixture.cache.clear()
            prime = self.fetch(fixture, f"/account/settings?bvcache={marker}", "proof-prime")
            replay = self.fetch(fixture, f"/account/settings?bvcache={marker}", "proof-replay")
            cross = self.fetch(fixture, "/account/settings", "proof-cross")
            roles = {
                "baseline": baseline.body,
                "test": b"prime\n" + prime.body,
                "replay": b"replay\n" + replay.body,
                "cross-viewer": cross.body,
            }
            artifacts = {role: self.artifact(role, body) for role, body in roles.items()}
            ids = [r.request_id for r in (baseline, prime, replay, cross)]
            with self.assertRaisesRegex(ValueError, "baseline/test/replay/cross-viewer"):
                self.ledger.record(self.event(cross.request_id, ids, "/account/settings",
                                              marker, artifacts))
            self.assertEqual(self.ctx.store.jobs(), [])

    def test_cache_config_is_fail_closed(self):
        config = json.loads((self.root / "scope.json").read_text())
        config["cache"] = {"rules_reviewed": "", "grants": ["write"], "budget": 0}
        (self.root / "scope.json").write_text(json.dumps(config))
        with self.assertRaises(ConfigError):
            Campaign.load(self.root)
        config["cache"] = {"rules_reviewed": "", "grants": [], "budget": 0}
        (self.root / "scope.json").write_text(json.dumps(config))
        Campaign.load(self.root)
        config["cache"] = {"rules_reviewed": "2026-11-20", "grants": ["unknown"], "budget": 1}
        (self.root / "scope.json").write_text(json.dumps(config))
        with self.assertRaises(ConfigError):
            Campaign.load(self.root)

    def test_private_policy_control_prevents_deception_storage(self):
        with CacheFixture() as fixture:
            fixture.respect_private = True
            owner = self.fetch(fixture, "/account/settings/profile.css", "policy-owner", viewer="owner")
            low = self.fetch(fixture, "/account/settings/profile.css", "policy-low")
            self.assertEqual(owner.status, 200)
            self.assertEqual(low.status, 403)
            self.assertNotIn(b"bvdeceive_owner_001a", low.body)
            self.assertEqual(fixture.cache, {})

    def test_transformed_key_is_a_local_collision_not_hostwide_assumption(self):
        with CacheFixture() as fixture:
            fixture.normalize_key = True
            encoded = self.fetch(fixture, "/variant/a%2Fb", "transform-fill")
            literal = self.fetch(fixture, "/variant/a/b", "transform-view")
            self.assertEqual(encoded.body, literal.body)
            self.assertEqual(literal.headers.get("x-cache"), "HIT")
            fixture.cache.clear()
            fixture.normalize_key = False
            encoded_fixed = self.fetch(fixture, "/variant/a%2Fb", "transform-fixed-fill")
            literal_fixed = self.fetch(fixture, "/variant/a/b", "transform-fixed-view")
            self.assertNotEqual(encoded_fixed.body, literal_fixed.body)
            self.assertEqual(literal_fixed.headers.get("x-cache"), "MISS")


if __name__ == "__main__":
    unittest.main()
