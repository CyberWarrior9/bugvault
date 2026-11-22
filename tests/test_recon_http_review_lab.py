"""Loopback-only defensive framing gate. It never proxies a captured message.

Messages being reviewed are base64 DATA inside an ordinary local JSON POST;
malformed HTTP is never put on a transport. This is not a desync exploitation lab.
"""
import base64
import http.client
import http.server
import json
import threading
import unittest

from recon.http_review import inspect_http1


class HttpFramingLoopbackTests(unittest.TestCase):
    def test_local_gate_rejects_ambiguous_capture_and_accepts_fixed_control(self):
        seen = []

        class Gate(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                if size > 4096 or self.path != "/review":
                    self.send_error(400)
                    return
                envelope = json.loads(self.rfile.read(size))
                raw = base64.b64decode(envelope["capture"], validate=True)
                result = inspect_http1(raw)
                seen.append(result["verdict"])
                body = json.dumps(result).encode()
                self.send_response(422 if result["verdict"] == "reject" else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gate)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        controls = [b"GET / HTTP/1.1\r\nHost: lab.invalid\r\n\r\n",
                    b"POST / HTTP/1.1\r\nHost: lab.invalid\r\nContent-Length: 0\r\n"
                    b"Content-Length: 0\r\n\r\n",
                    b"POST / HTTP/1.1\r\nHost: lab.invalid\r\nContent-Length: 0\r\n\r\n"]
        try:
            for raw, expected in zip(controls, (200, 422, 200)):
                body = json.dumps({"capture": base64.b64encode(raw).decode()})
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                try:
                    connection.request("POST", "/review", body=body,
                                       headers={"Content-Type": "application/json"})
                    response = connection.getresponse()
                    result = json.loads(response.read())
                    self.assertEqual(response.status, expected)
                    self.assertFalse(result["smuggling_confirmed"])
                finally:
                    connection.close()
            self.assertEqual(seen, ["well-formed-observation", "reject", "well-formed-observation"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
