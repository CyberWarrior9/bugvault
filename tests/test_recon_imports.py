"""Offline import adapters: Burp XML/JSON/raw exports (header/cookie NAMES only,
values dropped) and OpenAPI/Swagger specs (declared fields, no fetch)."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.burp import import_burp, parse_raw_request
from recon.fields import FieldLedger
from recon.pipeline import Recon
from recon.specs import import_openapi
from tests.test_recon import write_campaign

SECRET = "SESSVALUETOPSECRET"


def _raw_request(method, target, host, headers, body=b"", scheme_hint=None):
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    head = "\r\n".join(lines).encode() + b"\r\n\r\n"
    return head + body


def _burp_item(url, method, status, request, response=None):
    item = f"<item><url>{url}</url><method>{method}</method>"
    if status is not None:
        item += f"<status>{status}</status>"
    item += (f'<request base64="true"><![CDATA[{base64.b64encode(request).decode()}]]>'
             "</request>")
    if response is not None:
        item += (f'<response base64="true"><![CDATA[{base64.b64encode(response).decode()}]]>'
                 "</response>")
    return item + "</item>"


class BurpImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)

    def xml(self, items: str) -> Path:
        path = self.root / "burp.xml"
        path.write_text('<?xml version="1.0"?><items>' + items + "</items>")
        return path

    def test_xml_import_captures_names_and_stores_response(self):
        marker = "bv_1a2b3c4d"
        request = _raw_request(
            "POST", "/api/profile/314", "acme.test",
            {"Cookie": f"session={SECRET}; prefs=dark", "X-Request-Id": "abc-123",
             "Content-Type": "application/json"},
            json.dumps({"bio": f"<b>{marker}</b>", "template": "main"}).encode())
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    b"Set-Cookie: rotated=" + SECRET.encode() + b"\r\n\r\n"
                    b"<html>saved <b>" + marker.encode() + b"</b></html>")
        oos_request = _raw_request("GET", "/x", "other.test", {}, b"")
        path = self.xml(
            _burp_item("https://acme.test/api/profile/314", "POST", 200, request, response)
            + _burp_item("https://acme.test/static/logo.png", "GET", 200,
                         _raw_request("GET", "/static/logo.png", "acme.test", {}))
            + _burp_item("https://other.test/private", "GET", 200, oos_request))
        stats = import_burp(self.ctx, path, "alice", role="user", tenant="t1")
        self.assertEqual(stats["format"], "burp-xml")
        self.assertEqual(stats["items"], 3)
        self.assertEqual(stats["endpoints"], 1)
        self.assertEqual(stats["static"], 1)
        self.assertEqual(stats["out_of_scope"], 1)
        self.assertEqual(stats["responses_stored"], 1)
        self.assertEqual(stats["malformed"], 0)
        # endpoint + observation buckets include header/cookie NAMES
        assets = self.ctx.store.assets("endpoint")
        self.assertEqual(len(assets), 1)
        aid = assets[0]["id"]
        self.assertEqual(assets[0]["value"], "https://acme.test/api/profile/{id}")
        obs = self.ctx.store.observations(aid)[0]
        self.assertEqual(obs["account"], "alice")
        self.assertEqual(sorted(obs["params"]["header"]), ["cookie", "x-request-id"])
        self.assertEqual(sorted(obs["params"]["cookie"]), ["prefs", "session"])
        self.assertEqual(sorted(obs["params"]["body"]), ["bio", "template"])
        self.assertEqual(obs["context"]["basis"], "captured-real-traffic")
        # response stored for offline tracing; basis marks the import
        req_rows = self.ctx.store.db.execute("SELECT id, url FROM requests").fetchall()
        self.assertEqual(len(req_rows), 1)
        capture = self.ctx.store.db.execute(
            "SELECT basis FROM response_capture").fetchone()
        self.assertEqual(capture["basis"], "imported-burp-capture")
        # privacy: secret values appear nowhere in the database
        blob = self.camp.state_dir.joinpath("recon.db").read_bytes()
        self.assertNotIn(SECRET.encode(), blob)
        self.assertNotIn(b"abc-123", blob)          # header value dropped
        self.assertNotIn(b"dark", blob)             # cookie value dropped
        # Set-Cookie: the cookie NAME and its attributes are kept as CSRF capture
        # metadata (cookie-delivery analysis), like request cookie names; the value
        # (SECRET, asserted absent above) never is.
        meta = obs["context"]["csrf_meta"]
        self.assertEqual([c["name"] for c in meta["set_cookies"]], ["rotated"])
        self.assertIsNone(meta["set_cookies"][0]["samesite"])  # omitted, not "lax"
        self.assertEqual(meta["auth"], "cookie")
        self.assertEqual(meta["content_type"], "application/json")
        # provenance + import result recorded
        self.assertEqual(len(self.ctx.store.provenance_records()), 2)
        # canary that was never submitted leaves no trace; the imported capture
        # stays searchable (submitted-marker case is covered below)
        ledger = FieldLedger(self.ctx)
        ledger.sync(aid)
        canary = ledger.canary(aid, "bio", method="POST", location="json", account="alice")
        result = ledger.trace(canary["marker"])
        self.assertEqual(result["surfaces"], [])

    def test_marker_in_imported_response_is_traceable(self):
        marker = "bv_9f8e7d6c"
        request = _raw_request("POST", "/api/profile/314", "acme.test",
                               {"Content-Type": "application/json"},
                               json.dumps({"bio": "x"}).encode())
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>" \
                   + marker.encode() + b"</p>"
        path = self.xml(_burp_item("https://acme.test/api/profile/314", "POST", 200,
                                   request, response))
        import_burp(self.ctx, path, "alice")
        aid = self.ctx.store.assets("endpoint")[0]["id"]
        ledger = FieldLedger(self.ctx)
        ledger.sync(aid)
        canary = ledger.canary(aid, "bio")
        # replace the stored request body with the canary marker: the import stored
        # the ORIGINAL body, so trace must find the marker from the imported capture
        stored = ledger.trace(canary["marker"])
        # the marker was not sent, so only a response-side hit counts; here none
        self.assertEqual(stored["surfaces"], [])
        # now a canary actually submitted through the imported surface
        rid = self.ctx.store.db.execute("SELECT id FROM requests").fetchone()[0]
        body = json.dumps({"bio": canary["marker"]}).encode()
        self.ctx.store.db.execute(
            "INSERT OR REPLACE INTO request_payload(request_id, body_sha256, body_len,"
            " content_type) VALUES(?,?,?,?)",
            (rid, hashlib.sha256(body).hexdigest(), len(body), "application/json"))
        (self.camp.bodies_dir).mkdir(parents=True, exist_ok=True)
        (self.camp.bodies_dir / hashlib.sha256(body).hexdigest()).write_bytes(body)
        self.ctx.store.db.commit()
        stored = ledger.trace(canary["marker"])
        self.assertIn("submission-capture", stored["surfaces"])
        self.assertIn("same-response", stored["surfaces"])  # marker now in response too

    def test_json_import(self):
        marker = "bv_abcd1234"
        request = _raw_request("GET", "/api/users/314", "acme.test",
                               {"Cookie": f"s={SECRET}"})
        entry = {"url": "https://acme.test/api/users/314", "method": "GET", "status": 200,
                 "request": {"text": request.decode(), "base64": False}}
        path = self.root / "burp.json"
        path.write_text(json.dumps([entry]))
        stats = import_burp(self.ctx, path, "bob")
        self.assertEqual(stats["format"], "burp-json")
        self.assertEqual(stats["endpoints"], 1)
        obs = self.ctx.store.observations(self.ctx.store.assets("endpoint")[0]["id"])[0]
        self.assertIn("cookie", obs["params"]["header"])
        self.assertEqual(obs["params"]["cookie"], ["s"])
        blob = self.camp.state_dir.joinpath("recon.db").read_bytes()
        self.assertNotIn(SECRET.encode(), blob)

    def test_raw_request_import(self):
        request = _raw_request("POST", "/api/login", "acme.test",
                               {"Content-Type": "application/json"},
                               json.dumps({"user": "u", "pass": "p"}).encode())
        path = self.root / "req.txt"
        path.write_bytes(request)
        stats = import_burp(self.ctx, path, "carol", scheme="https")
        self.assertEqual(stats["format"], "raw-request")
        self.assertEqual(stats["endpoints"], 1)
        asset = self.ctx.store.assets("endpoint")[0]
        self.assertEqual(asset["value"], "https://acme.test/api/login")
        obs = self.ctx.store.observations(asset["id"])[0]
        self.assertEqual(obs["params"]["body"], ["user", "pass"])

    def test_raw_request_needs_host(self):
        with self.assertRaises(ValueError):
            parse_raw_request(b"GET /x HTTP/1.1\r\n\r\n")
        parsed = parse_raw_request(_raw_request("GET", "/y", "h.test", {}), scheme="https")
        self.assertEqual(parsed[1], "https://h.test/y")

    def test_garbage_file_raises_cleanly(self):
        path = self.root / "bad.xml"
        path.write_text("<items><unclosed>")
        with self.assertRaises(Exception):
            import_burp(self.ctx, path, "a")


class OpenApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "camp"
        self.camp = write_campaign(self.root, "active", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda _: None)
        self.addCleanup(self.ctx.store.close)

    def spec(self, data: dict) -> Path:
        path = self.root / "spec.json"
        path.write_text(json.dumps(data))
        return path

    def test_openapi3_fields_with_locations(self):
        schema = {"type": "object", "properties": {
            "bio": {"type": "string"},
            "profile": {"type": "object", "properties": {
                "theme": {"type": "string"}}}}}
        data = {"openapi": "3.0.1", "servers": [{"url": "https://acme.test/api"}],
                "paths": {
                    "/users/{id}": {
                        "get": {"parameters": [
                            {"name": "id", "in": "path", "required": True},
                            {"name": "q", "in": "query"},
                            {"name": "X-Trace", "in": "header"}]},
                        "put": {"requestBody": {"content": {"application/json": {
                            "schema": schema}}}}}}}
        with patch("socket.socket", side_effect=AssertionError("offline only")):
            stats = import_openapi(self.ctx, self.spec(data))
        self.assertEqual(stats["operations"], 2)
        self.assertEqual(stats["endpoints"], 2)
        get_asset = next(a for a in self.ctx.store.assets("endpoint")
                         if a["value"] == "https://acme.test/api/users/{id}"
                         and "GET" in a["attrs"]["methods"])
        fields = get_asset["attrs"]["spec_fields"]
        by_name = {f["name"]: f["location"] for f in fields}
        self.assertEqual(by_name["id"], "path")
        self.assertEqual(by_name["q"], "query")
        self.assertEqual(by_name["X-Trace"], "header")
        put_asset = next(a for a in self.ctx.store.assets("endpoint")
                         if "PUT" in a["attrs"]["methods"])
        put_names = {f["name"] for f in put_asset["attrs"]["spec_fields"]}
        self.assertIn("bio", put_names)
        self.assertIn("profile.theme", put_names)
        # ledger sync turns spec fields into per-location rows
        ledger = FieldLedger(self.ctx)
        ledger.sync(get_asset["id"])
        rows = ledger.db.execute(
            "SELECT DISTINCT location FROM field_ledger WHERE asset_id=?",
            (get_asset["id"],)).fetchall()
        locations = {r["location"] for r in rows}
        self.assertIn("path", locations)
        self.assertIn("header", locations)
        self.assertEqual(get_asset["attrs"]["bases"], ["openapi-spec"])

    def test_swagger2_host_basepath(self):
        data = {"swagger": "2.0", "host": "acme.test", "basePath": "/v2", "schemes":
                ["https"], "paths": {"/pets": {"get": {"parameters": [
                    {"name": "limit", "in": "query", "type": "integer"}]}}}}
        stats = import_openapi(self.ctx, self.spec(data))
        self.assertEqual(stats["endpoints"], 1)
        asset = self.ctx.store.assets("endpoint")[0]
        self.assertEqual(asset["value"], "https://acme.test/v2/pets")

    def test_out_of_scope_servers_become_nothing(self):
        data = {"openapi": "3.0.1", "servers": [{"url": "https://other.test"}],
                "paths": {"/x": {"get": {}}}}
        stats = import_openapi(self.ctx, self.spec(data))
        self.assertEqual(stats["endpoints"], 0)
        self.assertEqual(stats["out_of_scope"], 1)
        self.assertEqual(self.ctx.store.assets("intel")[0]["value"], "https://other.test")

    def test_unsupported_shapes_refused(self):
        with self.assertRaises(ValueError):
            import_openapi(self.ctx, self.spec({"openapi": "3.0.1"}))  # no paths
        with self.assertRaises(ValueError):  # no servers and no host
            import_openapi(self.ctx, self.spec({"openapi": "3.0.1", "paths": {}}))


if __name__ == "__main__":
    unittest.main()
