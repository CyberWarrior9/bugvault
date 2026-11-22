"""Owned-loopback contrasts: no target, shell, gadget or actual code execution."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from queue import Queue
import threading
import unittest

from recon.execproof import assess


class InertProcessor(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        mode, marker = request["mode"], request["marker"]
        if mode == "deferred":
            self.server.worker_log.put(b"processed data " + marker.encode())
            code, body = 202, b"queued for worker"
        elif mode == "error":
            code, body = 422, b"serialized format rejected"
        elif mode == "reflect":
            code, body = 200, marker.encode()
        elif mode == "negative":
            code, body = 200, b"fixed output " + marker.encode()
        else:
            code, body = 200, b"healthy output " + marker.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class RceLoopbackContrasts(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), InertProcessor)
        self.server.worker_log = Queue()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def attempt(self, mode, marker):
        blob = json.dumps({"mode": mode, "marker": marker}).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            conn.request("POST", "/report", body=blob, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            return blob, response.status, response.read()
        finally:
            conn.close()

    def bundle(self, mode):
        effect, replay, control = "owned_effect_1234567890", "owned_replay_1234567890", "owned_control_1234567890"
        _, _, baseline = self.attempt("healthy", "baseline-data")
        trigger, first_code, first = self.attempt(mode, effect)
        replay_request, second_code, second = self.attempt(mode, replay)
        if mode == "deferred":
            first_log = self.server.worker_log.get(timeout=2)
            second_log = self.server.worker_log.get(timeout=2)
        else:
            first_log, second_log = b"no worker", b"no worker"
        _, _, negative = self.attempt("negative", control)
        _, _, healthy = self.attempt("healthy", control)
        self.assertEqual((first_code, second_code), (202, 202) if mode == "deferred" else (200, 200))
        artifacts = {"baseline": baseline, "trigger": trigger, "replay-request": replay_request,
                     "effect": first_log if mode == "deferred" else first,
                     "verification": second_log if mode == "deferred" else second,
                     "negative-control": negative, "positive-control": healthy,
                     "cleanup": b"stateless local route, no objects created"}
        if mode == "deferred":
            artifacts.update({"worker-log": first_log, "worker-replay": second_log})
        claim = {"state": "execution-claimed", "channel": "owned-lab",
                 "effect_channel": "owner-worker-log" if mode == "deferred" else "direct-output",
                 "markers": {"effect": effect, "replay": replay, "control": control},
                 "binding": {"account": "owned", "role": "member", "tenant": "owned",
                             "workflow": "report", "consumer": "lab-worker", "owned_object": "stateless"},
                 "fidelity": {role: {"complete": True, "encoding": "identity"} for role in
                              ("baseline", "effect", "verification", "negative-control",
                               "positive-control")},
                 "times": {key: "2026-11-20T00:00:0%dZ" % i for i, key in enumerate(
                     ("baseline", "trigger", "replay", "negative", "cleanup"), 1)}}
        return claim, artifacts

    def test_reflected_output_is_not_execution_evidence(self):
        claim, artifacts = self.bundle("reflect")
        result = assess(claim, artifacts, qualified=True)
        self.assertEqual(result["assessment"], "inconclusive")
        self.assertIn("appears in a request", " ".join(result["reasons"]))

    def test_deferred_worker_log_of_client_data_is_not_execution_evidence(self):
        claim, artifacts = self.bundle("deferred")
        result = assess(claim, artifacts, qualified=True)
        self.assertEqual(result["assessment"], "inconclusive")
        self.assertFalse(result["verification_eligible"])

    def test_parser_error_and_processing_state_do_not_escalate(self):
        _, code, body = self.attempt("error", "serialized-looking-value")
        self.assertEqual(code, 422)
        self.assertIn(b"format rejected", body)
        claim = {"state": "observed", "effect_channel": "processing"}
        self.assertEqual(assess(claim, {"effect": body}, qualified=False)["assessment"],
                         "behavior-observed")


if __name__ == "__main__":
    unittest.main()
