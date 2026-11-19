"""Gate B: owned 127.0.0.1 upload lab for the offline upload ledger.

The service keeps uploads in memory and never interprets their content. It applies
an allowlist, a 1,024-byte per-file cap, a quarantine worker, static attachment
serving, a resumable endpoint with a 1,024-byte assembled cap, owner telemetry and a
URL import that can reach only this test's own loopback receiver. The ledger sends
nothing; every request in this file goes to 127.0.0.1.
"""
from datetime import datetime, timedelta, timezone
import http.client
import http.server
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import threading
import unittest
import uuid
import zlib
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.campaign import Campaign
from recon.pipeline import Recon
from recon.upload import UploadLedger, inert_issues
from tests.test_recon import write_campaign

MAX_FILE = 1024
ENVELOPE_MAX = 8192
ALLOWED = {"txt": "text/plain", "png": "image/png"}
PNG = b"\x89PNG\r\n\x1a\n"
BOUNDARY = "bvlab7f3a"
MARKER_RE = re.compile(rb"(bvup_[0-9a-f]{24})")


def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def multipart(filename, ctype, data):
    head = (f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n").encode()
    return head + data + f"\r\n--{BOUNDARY}--\r\n".encode(), f"multipart/form-data; boundary={BOUNDARY}"


def parse_multipart(body, content_type):
    match = re.search(r"boundary=([A-Za-z0-9_-]+)", content_type or "")
    if not match:
        return []
    parts = []
    for chunk in body.split(b"--" + match.group(1).encode())[1:]:
        if chunk.startswith(b"--"):
            break
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            return []
        text = head.decode("latin-1")
        name = re.search(r'name="([^"]*)"', text)
        filename = re.search(r'filename="([^"]*)"', text)
        ctype = re.search(r"Content-Type:\s*([^\r\n]+)", text, re.I)
        parts.append({"name": name.group(1) if name else "",
                      "filename": filename.group(1) if filename else None,
                      "type": ctype.group(1).strip().lower() if ctype else "",
                      "data": data[:-2] if data.endswith(b"\r\n") else data})
    return parts


class LabState:
    def __init__(self):
        self.lock = threading.Lock()
        self.objects, self.sessions, self.logs = {}, {}, []

    def log(self, request, layer, decision, **extra):
        with self.lock:
            self.logs.append({"request": request, "layer": layer, "decision": decision, **extra})

    def run_worker(self):
        with self.lock:
            pending = [o for o in self.objects.values() if o["state"] == "pending" and not o["slow"]]
        for obj in pending:
            found = MARKER_RE.search(obj["data"])
            marker = found.group(1).decode() if found else ""
            if b"reject-me" in obj["data"]:
                obj["state"] = "rejected"
                self.log(obj["request"], "worker", "rejected", job=obj["job"], marker=marker)
                continue
            if obj["ext"] == "png":
                obj["derivative"] = (obj["data"][:-12] + png_chunk(b"tEXt", b"Derived\x00lab-thumbnail") +
                                     obj["data"][-12:])
            obj["state"] = "ready"
            self.log(obj["request"], "worker", "processed", job=obj["job"], marker=marker)
        return len(pending)


def lab_handler(state, receiver_port):
    class Lab(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, status, body=b"", headers=None):
            self.send_response(status)
            if self.headers.get("X-Request-Id"):
                self.send_header("X-Request-Id", self.headers["X-Request-Id"])
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, data):
            self._send(status, json.dumps(data).encode(), {"Content-Type": "application/json"})

        def _read(self):
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(min(length, 2 * ENVELOPE_MAX + 1)) if length > 0 else b""

        def _ids(self):
            return self.headers.get("X-Request-Id", ""), self.headers.get("X-Lab-Account", "")

        def _owned(self, account, oid):
            obj = state.objects.get(oid)
            return obj if obj and obj["owner"] == account else None

        def _store(self, request, account, ext, data, name):
            oid, job = uuid.uuid4().hex[:16], "job-" + uuid.uuid4().hex[:8]
            with state.lock:
                state.objects[oid] = {"owner": account, "ext": ext, "data": data, "state": "pending",
                                      "job": job, "request": request, "name": f"{oid}.{ext}",
                                      "derivative": None, "slow": name.startswith("slow-")}
            state.log(request, "origin", "accepted", object=oid, job=job)
            self._json(201, {"id": oid, "state": "pending", "job": job})

        def do_POST(self):
            request, account = self._ids()
            path = urlsplit(self.path).path
            body = self._read()
            if self.headers.get("X-Lab-Edge") == "block":
                state.log(request, "edge", "block", rule="lab-upload-rule")
                return self._send(403, b"lab edge block page", {"X-Lab-Edge-Decision": "block"})
            if len(body) > ENVELOPE_MAX:
                state.log(request, "edge", "envelope-too-large", bytes=len(body))
                return self._send(413, b"lab edge envelope limit", {"X-Lab-Edge-Decision": "size"})
            if path == "/upload":
                files = [p for p in parse_multipart(body, self.headers.get("Content-Type"))
                         if p["name"] == "file" and p["filename"] is not None]
                if len(files) != 1:
                    state.log(request, "origin", "malformed")
                    return self._json(400, {"error": "exactly one file field"})
                item = files[0]
                ext = item["filename"].rsplit(".", 1)[-1].lower() if "." in item["filename"] else ""
                if ext not in ALLOWED:
                    decision, status = "extension-not-allowed", 415
                elif item["type"] != ALLOWED[ext]:
                    decision, status = "declared-type-mismatch", 415
                elif len(item["data"]) > MAX_FILE:
                    decision, status = "file-too-large", 413
                elif (ext == "png") != item["data"].startswith(PNG) or ext == "txt" and b"\x00" in item["data"]:
                    decision, status = "content-mismatch", 422
                else:
                    return self._store(request, account, ext, item["data"], item["filename"])
                state.log(request, "origin", decision, bytes=len(item["data"]))
                return self._json(status, {"error": decision})
            if path == "/upload/resumable":
                try:
                    total = json.loads(body or b"{}").get("total")
                except (ValueError, AttributeError):
                    total = None
                if type(total) is not int or not 0 < total <= MAX_FILE:
                    state.log(request, "origin", "declared-total-refused")
                    return self._json(413, {"error": "declared total"})
                sid = uuid.uuid4().hex[:12]
                with state.lock:
                    state.sessions[sid] = {"owner": account, "total": total, "parts": []}
                state.log(request, "origin", "session-created", session=sid)
                return self._json(201, {"session": sid})
            match = re.fullmatch(r"/upload/resumable/([0-9a-f]{12})/finalize", path)
            if match:
                session = state.sessions.get(match.group(1))
                if not session or session["owner"] != account:
                    return self._json(404, {"error": "not found"})
                data = b"".join(session["parts"])
                if len(data) > MAX_FILE or len(data) != session["total"]:
                    state.log(request, "origin", "assembled-size-refused", bytes=len(data))
                    return self._json(413, {"error": "assembled size"})
                with state.lock:
                    del state.sessions[match.group(1)]
                return self._store(request, account, "txt", data, "assembled.txt")
            if path == "/import":
                try:
                    target = urlsplit(json.loads(body or b"{}").get("url", ""))
                except (ValueError, AttributeError):
                    target = urlsplit("")
                if target.scheme != "http" or target.hostname != "127.0.0.1" or target.port != receiver_port:
                    state.log(request, "origin", "destination-not-allowed")
                    return self._json(400, {"error": "destination not allowed"})
                job = "job-" + uuid.uuid4().hex[:8]
                conn = http.client.HTTPConnection("127.0.0.1", receiver_port, timeout=2)
                try:
                    conn.request("GET", target.path, headers={"X-Lab-Job": job})
                    conn.getresponse().read()
                finally:
                    conn.close()
                state.log(request, "worker", "fetched", job=job, path=target.path)
                return self._json(202, {"job": job})
            if path == "/owner/worker/run":
                return self._json(200, {"processed": state.run_worker()})
            return self._json(404, {"error": "unknown route"})

        def do_PATCH(self):
            _, account = self._ids()
            body = self._read()
            match = re.fullmatch(r"/upload/resumable/([0-9a-f]{12})", urlsplit(self.path).path)
            session = state.sessions.get(match.group(1)) if match else None
            if not session or session["owner"] != account:
                return self._json(404, {"error": "not found"})
            with state.lock:
                session["parts"].append(body)
            return self._send(204)

        def do_GET(self):
            _, account = self._ids()
            parsed = urlsplit(self.path)
            if parsed.path == "/owner/logs":
                query = parse_qs(parsed.query)
                request, job = query.get("request", [""])[0], query.get("job", [""])[0]
                with state.lock:
                    rows = [dict(r) for r in state.logs
                            if request and r["request"] == request or job and r.get("job") == job]
                return self._json(200, rows)
            if parsed.path == "/owner/inventory":
                with state.lock:
                    data = {"objects": len(state.objects), "sessions": len(state.sessions),
                            "parts": sum(len(s["parts"]) for s in state.sessions.values())}
                return self._json(200, data)
            match = re.fullmatch(r"/files/([0-9a-f]{16})(/derivative)?", parsed.path)
            obj = self._owned(account, match.group(1)) if match else None
            if obj is None:
                return self._json(404, {"error": "not found"})
            if obj["state"] == "pending":
                return self._json(409, {"state": "pending"})
            if obj["state"] == "rejected":
                return self._json(410, {"state": "rejected"})
            if match.group(2):
                if obj["derivative"] is None:
                    return self._json(404, {"error": "no derivative"})
                return self._send(200, obj["derivative"], {
                    "Content-Type": "image/png", "X-Content-Type-Options": "nosniff",
                    "Content-Disposition": f'attachment; filename="{obj["name"]}-thumb.png"'})
            return self._send(200, obj["data"], {
                "Content-Type": ALLOWED[obj["ext"]], "X-Content-Type-Options": "nosniff",
                "Content-Disposition": f'attachment; filename="{obj["name"]}"',
                "Cache-Control": "private, no-store"})

        def do_DELETE(self):
            _, account = self._ids()
            path = urlsplit(self.path).path
            match = re.fullmatch(r"/files/([0-9a-f]{16})", path)
            if match and self._owned(account, match.group(1)):
                with state.lock:
                    obj = state.objects.pop(match.group(1))
                return self._json(200, {"deleted": match.group(1),
                                        "derivatives": int(obj["derivative"] is not None)})
            match = re.fullmatch(r"/upload/resumable/([0-9a-f]{12})", path)
            session = state.sessions.get(match.group(1)) if match else None
            if session and session["owner"] == account:
                with state.lock:
                    state.sessions.pop(match.group(1))
                return self._json(200, {"aborted": match.group(1), "parts": len(session["parts"])})
            return self._json(404, {"error": "not found"})

    return Lab


def receiver_handler(hits):
    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/health":
                body, status = b"receiver healthy", 200
            else:
                hits.append({"path": self.path, "job": self.headers.get("X-Lab-Job", ""),
                             "at": datetime.now(timezone.utc).isoformat()})
                body, status = b"", 204
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Receiver


class OwnedUploadLab(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state, self.hits = LabState(), []
        self.rport = self.serve(receiver_handler(self.hits)).server_address[1]
        self.origin = f"http://127.0.0.1:{self.serve(lab_handler(self.state, self.rport)).server_address[1]}"
        self.root = Path(self.temp.name) / "camp"
        write_campaign(self.root, "active", [], in_scope=["127.0.0.1"])
        raw = json.loads((self.root / "scope.json").read_text())
        raw["program_url"] = "https://owned.lab.test/policy"
        raw["policy"]["allowed_methods"] = ["GET", "HEAD", "POST", "PATCH", "DELETE"]
        raw["upload"] = {"rules_reviewed": "2026-11-14",
                         "case_grants": ["contrast", "transport", "derivative", "callback"],
                         "budget": {"requests": 10, "per_host": 10, "bytes": 10000, "objects": 5},
                         "callback_hosts": ["127.0.0.1", "*.oob.lab.test"]}
        (self.root / "scope.json").write_text(json.dumps(raw))
        self.ctx = Recon(Campaign.load(self.root), log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.ledger = UploadLedger(self.ctx)
        for path, params, ctype in (("/upload", ["file"], "multipart/form-data"),
                                    ("/upload/resumable", ["total"], "application/json"),
                                    ("/import", ["url"], "application/json")):
            aid = self.ctx.add_endpoint(self.origin + path, "har", method="POST", params=params,
                                        extra={"content_types": [ctype]})
            self.ctx.store.add_observation(
                aid, "POST", "a", {"query": [], "body": params, "header": [], "cookie": [], "ids": {}},
                201, "owned-lab", capture_key=f"lab:{path}",
                context={"role": "user", "tenant": "t1", "workflow_state": "lab",
                         "csrf_meta": {"content_type": ctype}})
        self.ledger.sync()
        self.contexts = {urlsplit(card["url"]).path: (card["transport"], card["contexts"][0]["context_id"])
                         for card in self.ledger.plan(limit=10)["sinks"]}
        self.assertEqual({path: transport for path, (transport, _) in self.contexts.items()},
                         {"/upload": "multipart", "/upload/resumable": "resumable",
                          "/import": "url-import"})

    def serve(self, handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def call(self, method, path, body=b"", headers=None, account="a", origin=None):
        url = (origin or self.origin) + path
        parts = urlsplit(url)
        if parts.scheme != "http" or parts.hostname != "127.0.0.1":
            raise AssertionError("owned loopback only")
        rid = "req-" + uuid.uuid4().hex[:12]
        sent = {"X-Request-Id": rid, "X-Lab-Account": account, **(headers or {})}
        conn = http.client.HTTPConnection("127.0.0.1", parts.port, timeout=3)
        try:
            conn.request(method, parts.path + ("?" + parts.query if parts.query else ""),
                         body=body or None, headers=sent)
            response = conn.getresponse()
            data, status = response.read(20000), response.status
            received = {k.lower(): v for k, v in response.getheaders()}
        finally:
            conn.close()
        request_id = self.ctx.store.record_request(
            method, url, status, "owned-loopback", sent.keys(), received, body=data,
            body_complete=True, basis="owned-loopback", req_body=body,
            req_content_type=sent.get("Content-Type"))
        return {"status": status, "headers": received, "body": data, "rid": rid,
                "request_id": request_id, "sent_bytes": len(body)}

    def upload(self, filename, data, ctype, headers=None):
        body, content_type = multipart(filename, ctype, data)
        return self.call("POST", "/upload", body, {"Content-Type": content_type, **(headers or {})})

    def fixture(self, kind="text", size=None):
        result = self.ledger.fixture(kind, size)
        result["data"] = (self.root / result["path"]).read_bytes()
        return result

    def save(self, name, data):
        path = self.root / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return "evidence/" + name

    def evidence(self, name, response):
        return self.save(name, b"HTTP %d\n" % response["status"] +
                         json.dumps(response["headers"], sort_keys=True).encode() + b"\n" + response["body"])

    def owner_log(self, name, layer, request=None, job=None):
        query = f"request={request}" if request else f"job={job}"
        rows = json.loads(self.call("GET", "/owner/logs?" + query)["body"])
        return self.save(name, json.dumps([r for r in rows if r["layer"] == layer]))

    def record(self, sink, case, state, **kw):
        kw.setdefault("channel", "lab")
        return self.ledger.record(self.contexts[sink][1], case, state, **kw)

    def delete(self, event, oid, name):
        gone = self.call("DELETE", f"/files/{oid}")
        self.assertEqual(gone["status"], 200)
        return self.ledger.cleanup(event["event_id"], "deleted", self.evidence(name, gone), "owned lab delete")

    def assert_clean(self):
        inventory = json.loads(self.call("GET", "/owner/inventory")["body"])
        self.assertEqual(inventory, {"objects": 0, "sessions": 0, "parts": 0})
        status = self.ledger.status()
        self.assertEqual(status["pending_cleanup"], [])
        self.assertTrue(status["integrity"]["verified"], status["integrity"])
        urls = [r["url"] for r in self.ctx.store.db.execute("SELECT url FROM requests")]
        self.assertTrue(urls and all(urlsplit(u).hostname == "127.0.0.1" for u in urls))
        self.assertEqual(self.ctx.store.network_attempts(), 0)

    def test_b01_normal_lifecycle(self):
        fx = self.fixture()
        up = self.upload(f"{fx['marker']}.txt", fx["data"], "text/plain")
        self.assertEqual(up["status"], 201)
        oid = json.loads(up["body"])["id"]
        self.assertEqual(self.call("GET", f"/files/{oid}")["status"], 409)
        self.call("POST", "/owner/worker/run")
        got = self.call("GET", f"/files/{oid}")
        self.assertEqual((got["status"], got["body"]), (200, fx["data"]))
        result = self.record(
            "/upload", "intake-normal", "accepted-inert", marker=fx["marker"],
            control_marker=fx["control_marker"],
            facts=["accepted=yes", "stored=yes", "reachable=yes", "served=yes"],
            artifacts=[f"original={fx['path']}", f"control={fx['control_path']}",
                       f"response={self.evidence('b01-up', up)}",
                       f"retrieval={self.evidence('b01-get', got)}"],
            requests=4, bytes_sent=up["sent_bytes"], objects=1, object_ref=oid)
        self.assertTrue(result["known_fixture"])
        self.assertEqual((result["facts"]["executed"], result["eligible_for_review"]), ("unknown", False))
        self.assertTrue(self.delete(result, oid, "b01-delete")["resolved"])
        self.assert_clean()

    def test_b02_format_policy(self):
        valid, extension, wrong = self.fixture(), self.fixture(), self.fixture()
        accepted = self.upload(f"{valid['marker']}.txt", valid["data"], "text/plain")
        refused_ext = self.upload(f"{extension['marker']}.data", extension["data"], "text/plain")
        refused_fmt = self.upload(f"{wrong['marker']}.png", wrong["data"], "image/png")
        self.assertEqual((accepted["status"], refused_ext["status"], refused_fmt["status"]), (201, 415, 422))
        oid = json.loads(accepted["body"])["id"]
        control = self.record("/upload", "intake-normal", "accepted-inert", marker=valid["marker"],
                              facts=["accepted=yes"], requests=1, objects=1, object_ref=oid,
                              artifacts=[f"original={valid['path']}",
                                         f"response={self.evidence('b02-valid', accepted)}"])
        for case, fx, response, decision in (
                ("contrast-extension", extension, refused_ext, "extension-not-allowed"),
                ("contrast-format", wrong, refused_fmt, "content-mismatch")):
            log = self.owner_log(f"b02-{case}-log", "origin", request=response["rid"])
            self.assertIn(decision, (self.root / log).read_text())
            result = self.record(
                "/upload", case, "rejected", marker=fx["marker"], facts=["accepted=no"],
                layer="origin", request_ref=response["rid"], response_status=response["status"],
                artifacts=[f"original={fx['path']}", f"response={self.evidence('b02-' + case, response)}",
                           f"origin-log={log}"],
                requests=1, note="Lab policy refused the inert contrast; the valid control was accepted")
            self.assertEqual((result["attribution"], result["layer"], result["eligible_for_review"]),
                             ("layer-correlated", "origin", False))
        self.delete(control, oid, "b02-delete")
        self.assert_clean()

    def test_b03_tiny_size_boundary(self):
        for size, expected in ((1023, 201), (1024, 201), (1025, 413)):
            with self.subTest(size=size):
                fx = self.fixture(size=size)
                self.assertEqual(len(fx["data"]), size)
                up = self.upload(f"{fx['marker']}.txt", fx["data"], "text/plain")
                self.assertEqual(up["status"], expected)
                envelope = self.ctx.store.request_payload(up["request_id"])["body_len"]
                self.assertGreater(envelope, size)  # multipart envelope is counted separately
                name = "b03-%d" % size
                artifacts = [f"original={fx['path']}", f"response={self.evidence(name, up)}"]
                if expected == 201:
                    oid = json.loads(up["body"])["id"]
                    event = self.record("/upload", "size-boundary", "accepted-inert", marker=fx["marker"],
                                        facts=["accepted=yes"], artifacts=artifacts, requests=1,
                                        bytes_sent=envelope, objects=1, object_ref=oid)
                    self.delete(event, oid, name + "-delete")
                else:
                    log = self.owner_log(name + "-log", "origin", request=up["rid"])
                    self.assertIn("file-too-large", (self.root / log).read_text())
                    self.record("/upload", "size-boundary", "rejected", marker=fx["marker"],
                                facts=["accepted=no"], layer="origin", request_ref=up["rid"],
                                artifacts=artifacts + [f"origin-log={log}"], response_status=413,
                                requests=1, bytes_sent=envelope,
                                note="Lab cap refused 1,025 file bytes before publication")
        self.assert_clean()

    def test_b04_async_visibility(self):
        fx = self.fixture()
        up = self.upload(f"{fx['marker']}.txt", fx["data"], "text/plain")
        oid = json.loads(up["body"])["id"]
        self.assertEqual(self.call("GET", f"/files/{oid}")["status"], 409)
        artifacts = [f"original={fx['path']}", f"response={self.evidence('b04-up', up)}"]
        pending = self.record("/upload", "quarantine-scan", "pending", marker=fx["marker"],
                              facts=["accepted=yes"], artifacts=artifacts, requests=2, objects=1,
                              object_ref=oid)
        self.call("POST", "/owner/worker/run")
        ready = self.call("GET", f"/files/{oid}")
        self.assertEqual(ready["status"], 200)
        self.record("/upload", "quarantine-scan", "accepted-inert", marker=fx["marker"],
                    facts=["accepted=yes", "served=yes"], requests=2,
                    artifacts=artifacts + [f"retrieval={self.evidence('b04-ready', ready)}"])
        slow = self.fixture()
        stuck = self.upload(f"slow-{slow['marker']}.txt", slow["data"], "text/plain")
        sid = json.loads(stuck["body"])["id"]
        self.call("POST", "/owner/worker/run")
        self.assertEqual(self.call("GET", f"/files/{sid}")["status"], 409)
        waiting = self.record("/upload", "quarantine-scan", "inconclusive", marker=slow["marker"],
                              facts=["accepted=yes"], requests=3, objects=1, object_ref=sid,
                              artifacts=[f"original={slow['path']}",
                                         f"response={self.evidence('b04-slow', stuck)}"],
                              note="Observation window ended while pending; not a negative")
        self.assertEqual(waiting["state"], "inconclusive")
        self.assertIn("inconclusive", [row[3] for row in self.ledger.status()["open"]
                                       if row[2] == "quarantine-scan"])
        self.delete(pending, oid, "b04-delete")
        self.delete(waiting, sid, "b04-slow-delete")
        self.assert_clean()

    def test_b05_resumable_total(self):
        marker = self.fixture()["marker"]
        line = f"bugvault inert part\nmarker={marker}\n".encode()

        def session():
            opened = self.call("POST", "/upload/resumable", json.dumps({"total": 1000}).encode(),
                               {"Content-Type": "application/json"})
            self.assertEqual(opened["status"], 201)
            return json.loads(opened["body"])["session"]

        good = session()
        for part in (line + b"." * (500 - len(line)), b"." * 500):
            self.assertEqual(self.call("PATCH", f"/upload/resumable/{good}", part)["status"], 204)
        final = self.call("POST", f"/upload/resumable/{good}/finalize")
        self.assertEqual(final["status"], 201)
        oid = json.loads(final["body"])["id"]
        bad = session()
        for part in (line + b"." * (600 - len(line)), b"." * 600):
            self.assertEqual(self.call("PATCH", f"/upload/resumable/{bad}", part)["status"], 204)
        refused = self.call("POST", f"/upload/resumable/{bad}/finalize")
        self.assertEqual(refused["status"], 413)
        log = self.owner_log("b05-log", "origin", request=refused["rid"])
        self.assertIn("assembled-size-refused", (self.root / log).read_text())
        aborted = self.call("DELETE", f"/upload/resumable/{bad}")
        self.assertEqual(json.loads(aborted["body"]), {"aborted": bad, "parts": 2})
        ok = self.record("/upload/resumable", "resumable-assembly", "accepted-inert", marker=marker,
                         facts=["accepted=yes"], requests=4, bytes_sent=1000, objects=1,
                         object_ref=oid, artifacts=[f"response={self.evidence('b05-final', final)}"])
        no = self.record("/upload/resumable", "resumable-assembly", "rejected", marker=marker,
                         facts=["accepted=no"], layer="origin", request_ref=refused["rid"],
                         response_status=413, requests=4, bytes_sent=1200, objects=1, object_ref=bad,
                         artifacts=[f"response={self.evidence('b05-refused', refused)}",
                                    f"origin-log={log}"],
                         note="Each 600-byte part was under the cap; the assembled 1,200 bytes were refused")
        self.assertTrue(self.ledger.cleanup(no["event_id"], "aborted", self.evidence("b05-abort", aborted),
                                            "aborted the refused session")["resolved"])
        self.delete(ok, oid, "b05-delete")
        self.assert_clean()

    def test_b06_derived_content(self):
        fx = self.fixture("png")
        up = self.upload(f"{fx['marker']}.png", fx["data"], "image/png")
        self.assertEqual(up["status"], 201)
        created = json.loads(up["body"])
        self.call("POST", "/owner/worker/run")
        derived = self.call("GET", f"/files/{created['id']}/derivative")
        self.assertEqual(derived["status"], 200)
        self.assertNotEqual(derived["body"], fx["data"])
        self.assertIn(fx["marker"].encode(), derived["body"])
        self.assertEqual(inert_issues(derived["body"], "png"), [])
        worker = self.owner_log("b06-worker", "worker", job=created["job"])
        self.assertIn(fx["marker"], (self.root / worker).read_text())
        result = self.record("/upload", "derivative-metadata", "accepted-inert", marker=fx["marker"],
                             facts=["accepted=yes", "processed=yes"], requests=3, objects=1,
                             object_ref=created["id"],
                             artifacts=[f"original={fx['path']}", f"response={self.evidence('b06-up', up)}",
                                        f"derivative={self.save('b06-thumb.png', derived['body'])}",
                                        f"worker-log={worker}"])
        self.assertEqual((result["facts"]["processed"], result["facts"]["executed"], result["route"]),
                         ("yes", "unknown", None))
        gone = self.call("DELETE", f"/files/{created['id']}")
        self.assertEqual(json.loads(gone["body"])["derivatives"], 1)
        self.ledger.cleanup(result["event_id"], "deleted", self.evidence("b06-delete", gone), "deleted")
        self.assert_clean()

    def test_b07_static_serving(self):
        fx = self.fixture()
        up = self.upload(f"{fx['marker']}.txt", fx["data"], "text/plain")
        oid = json.loads(up["body"])["id"]
        self.call("POST", "/owner/worker/run")
        got = self.call("GET", f"/files/{oid}")
        headers = {k: got["headers"][k] for k in ("content-type", "content-disposition",
                                                   "x-content-type-options")}
        self.assertEqual(headers["content-type"], "text/plain")
        self.assertTrue(headers["content-disposition"].startswith("attachment"))
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(inert_issues(got["body"], "text"), [])
        args = {"marker": fx["marker"], "facts": ["accepted=yes", "stored=yes", "served=yes"],
                "artifacts": [f"response={self.evidence('b07-up', up)}",
                              f"retrieval={self.evidence('b07-get', got)}"], "requests": 3}
        with self.assertRaisesRegex(ValueError, "Content-Type"):
            self.record("/upload", "retrieval-policy", "accepted-inert", **args)
        result = self.record("/upload", "retrieval-policy", "accepted-inert", served_headers=headers,
                             objects=1, object_ref=oid, **args)
        stored = self.ctx.store.db.execute("SELECT served_headers FROM upload_events WHERE id=?",
                                           (result["event_id"],)).fetchone()["served_headers"]
        self.assertEqual(json.loads(stored), headers)
        self.delete(result, oid, "b07-delete")
        self.assert_clean()

    def test_b08_local_receiver_attribution(self):
        fx = self.fixture()
        marker, control = fx["marker"], fx["control_marker"]
        receiver = f"http://127.0.0.1:{self.rport}"
        health = self.call("GET", "/health", origin=receiver)
        self.assertEqual(health["body"], b"receiver healthy")
        sent = datetime.now(timezone.utc)
        imported = self.call("POST", "/import", json.dumps({"url": f"{receiver}/{marker}"}).encode(),
                             {"Content-Type": "application/json"})
        self.assertEqual(imported["status"], 202)
        job = json.loads(imported["body"])["job"]
        refused = self.call("POST", "/import", json.dumps({"url": "http://192.0.2.1/x"}).encode(),
                            {"Content-Type": "application/json"})
        self.assertEqual(refused["status"], 400)
        self.assertEqual([hit["path"] for hit in self.hits], [f"/{marker}"])
        attempt = self.record("/import", "url-import", "attempted", marker=marker, requests=1,
                              artifacts=[f"response={self.evidence('b08-import', imported)}"])
        event = attempt["event_id"]
        healthy = f"receiver-health={self.evidence('b08-health', health)}"
        log = f"receiver-log={self.save('b08-receiver.json', json.dumps(self.hits))}"
        window = {"sent_at": sent.isoformat(), "observed_at": self.hits[0]["at"],
                  "deadline": (sent + timedelta(minutes=1)).isoformat(), "control_marker": control,
                  "artifacts": [healthy, log]}
        url = f"{receiver}/{marker}"
        fetch = self.ledger.callback(event, "http", url, **window)
        self.assertEqual((fetch["classification"], fetch["proves_execution"]), ("fetch-observed", False))
        worker = f"worker-log={self.owner_log('b08-worker', 'worker', job=job)}"
        traced = self.ledger.callback(event, "worker-trace", url, job_id=job,
                                      **{**window, "artifacts": [healthy, log, worker]})
        self.assertEqual(traced["classification"], "processor-attributed")
        dns_log = f"receiver-log={self.save('b08-dns.txt', 'query ' + marker + '.oob.lab.test A')}"
        dns = self.ledger.callback(event, "dns", f"{marker}.oob.lab.test",
                                   **{**window, "artifacts": [healthy, dns_log]})
        self.assertEqual(dns["classification"], "resolution-observed")
        late = self.ledger.callback(event, "http", url, **{
            **window, "deadline": (sent + timedelta(microseconds=1)).isoformat()})
        self.assertEqual(late["classification"], "inconclusive-late")
        mixed = f"receiver-log={self.save('b08-mixed.json', json.dumps(self.hits + [{'path': '/' + control}]))}"
        with self.assertRaisesRegex(ValueError, "negative-control token reached"):
            self.ledger.callback(event, "http", url, **{**window, "artifacts": [healthy, mixed]})
        self.assertEqual(len(self.hits), 1)
        self.assert_clean()

    def test_b09_edge_origin_worker_and_timeout_stay_separate(self):
        edge_fx, origin_fx, worker_fx, slow_fx = (self.fixture() for _ in range(4))
        edge = self.upload(f"{edge_fx['marker']}.txt", edge_fx["data"], "text/plain", {"X-Lab-Edge": "block"})
        origin = self.upload(f"{origin_fx['marker']}.data", origin_fx["data"], "text/plain")
        worker_data = worker_fx["data"] + b"reject-me\n"
        worker_original = self.save("b09-worker-original.txt", worker_data)
        worker = self.upload(f"{worker_fx['marker']}.txt", worker_data, "text/plain")
        slow = self.upload(f"slow-{slow_fx['marker']}.txt", slow_fx["data"], "text/plain")
        self.assertEqual([r["status"] for r in (edge, origin, worker, slow)], [403, 415, 201, 201])
        worker_obj, slow_id = json.loads(worker["body"]), json.loads(slow["body"])["id"]
        self.call("POST", "/owner/worker/run")
        worker_get = self.call("GET", f"/files/{worker_obj['id']}")
        self.assertEqual((worker_get["status"], self.call("GET", f"/files/{slow_id}")["status"]), (410, 409))
        edge_log = self.owner_log("b09-edge", "edge", request=edge["rid"])
        origin_for_edge = self.owner_log("b09-origin-for-edge", "origin", request=edge["rid"])
        self.assertEqual(json.loads((self.root / origin_for_edge).read_text()), [])
        events = {"edge": self.record(
            "/upload", "edge-callback", "blocked", marker=edge_fx["marker"], layer="edge",
            request_ref=edge["rid"], response_status=403, requests=1,
            artifacts=[f"response={self.evidence('b09-edge-response', edge)}", f"edge-log={edge_log}"],
            note="Lab edge rule refused the request before the origin")}
        with self.assertRaisesRegex(ValueError, "request reference"):
            self.record("/upload", "edge-callback", "blocked", marker=edge_fx["marker"], layer="origin",
                        request_ref=edge["rid"], response_status=403,
                        artifacts=[f"response={self.evidence('b09-edge-again', edge)}",
                                   f"origin-log={origin_for_edge}"],
                        note="The same 403 cannot be attributed to the origin")
        origin_log = self.owner_log("b09-origin", "origin", request=origin["rid"])
        events["origin"] = self.record(
            "/upload", "contrast-extension", "rejected", marker=origin_fx["marker"], facts=["accepted=no"],
            layer="origin", request_ref=origin["rid"], response_status=415, requests=1,
            artifacts=[f"original={origin_fx['path']}", f"response={self.evidence('b09-origin', origin)}",
                       f"origin-log={origin_log}"],
            note="Origin allowlist refused the inert extension")
        worker_log = self.owner_log("b09-worker", "worker", job=worker_obj["job"])
        events["worker"] = self.record(
            "/upload", "quarantine-scan", "rejected", marker=worker_fx["marker"],
            facts=["accepted=yes", "processed=yes", "served=no"], layer="worker",
            request_ref=worker_obj["job"], requests=3, objects=1, object_ref=worker_obj["id"],
            artifacts=[f"original={worker_original}",
                       f"response={self.evidence('b09-worker-response', worker)}",
                       f"retrieval={self.evidence('b09-worker-get', worker_get)}",
                       f"worker-log={worker_log}"],
            note="Worker refused the file after the origin accepted it")
        events["timeout"] = self.record(
            "/upload", "quarantine-scan", "inconclusive", marker=slow_fx["marker"], facts=["accepted=yes"],
            requests=3, objects=1, object_ref=slow_id,
            artifacts=[f"original={slow_fx['path']}", f"response={self.evidence('b09-slow', slow)}"],
            note="No final state inside the observation window")
        self.assertEqual({k: (v["layer"], v["attribution"]) for k, v in events.items()},
                         {"edge": ("edge", "layer-correlated"), "origin": ("origin", "layer-correlated"),
                          "worker": ("worker", "layer-correlated"),
                          "timeout": ("unconfirmed", "layer-unconfirmed")})
        self.delete(events["worker"], worker_obj["id"], "b09-worker-delete")
        self.delete(events["timeout"], slow_id, "b09-slow-delete")
        self.assert_clean()

    def test_b10_cleanup_receipts_and_loopback_only(self):
        recorded = []
        for fx in (self.fixture(), self.fixture()):
            up = self.upload(f"{fx['marker']}.txt", fx["data"], "text/plain")
            oid = json.loads(up["body"])["id"]
            recorded.append((fx, oid, self.record(
                "/upload", "intake-normal", "accepted-inert", marker=fx["marker"], facts=["accepted=yes"],
                requests=1, objects=1, object_ref=oid,
                artifacts=[f"original={fx['path']}", f"response={self.evidence('b10-' + oid, up)}"])))
        (first_fx, first_id, first), (second_fx, second_id, second) = recorded
        self.delete(first, first_id, "b10-first-delete")
        lost = self.ledger.cleanup(second["event_id"], "unverified",
                                   note="Delete response was lost; object state unknown")
        self.assertEqual(lost["stopped_host"], "127.0.0.1")
        with self.assertRaisesRegex(ValueError, "is stopped"):
            self.record("/upload", "intake-normal", "attempted", marker=second_fx["marker"], requests=1)
        with self.assertRaisesRegex(ValueError, "resolve the failed cleanup"):
            self.ledger.resume("127.0.0.1", "retrying")
        self.delete(second, second_id, "b10-second-delete")
        self.assertEqual(self.ledger.resume("127.0.0.1", "Second object confirmed deleted in the owned lab")
                         ["cleared"], ["cleanup-unresolved"])
        self.assertEqual(self.ledger.status()["stopped_hosts"], [])
        bases = {r["basis"] for r in self.ctx.store.db.execute("SELECT basis FROM response_capture")}
        self.assertEqual(bases, {"owned-loopback"})
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
