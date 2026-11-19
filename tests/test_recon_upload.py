"""Gate A: offline file-upload lifecycle ledger. No DNS, target or receiver traffic."""
import contextlib
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.campaign import Campaign, ConfigError, OutOfScope, scope_template, validate_upload
from recon.cli import main
from recon.findings import CHAIN_HINTS, Findings
from recon.pipeline import Recon
from recon.report import write_reports
from recon.skillmap import SKILLS_DIR, skills_for
from recon.upload import CASES, UploadLedger, inert_issues

MARKER = "bvup_owned_marker_000001"
CONTROL = "bvctl_owned_control_00001"
GRANTS = ["contrast", "transport", "derivative", "callback", "cross-account"]
TIMES = {"sent_at": "2026-11-14T10:00:00Z", "observed_at": "2026-11-14T10:00:05Z",
         "deadline": "2026-11-14T10:05:00Z"}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "campaign"
        self.root.mkdir()
        cfg = scope_template("owned-lab", [], "active", ["POST", "PUT", "PATCH", "DELETE"])
        cfg["in_scope"] = ["lab.test"]
        cfg["program_url"] = "https://lab.test/program-policy"
        cfg["upload"] = {"rules_reviewed": "2026-11-14", "case_grants": list(GRANTS),
                         "budget": {"requests": 40, "per_host": 30, "bytes": 20000, "objects": 10},
                         "callback_hosts": ["*.oob.lab.test"], "retention_days": 7}
        self.cfg = cfg
        self.ctx = None
        self.reconfigure()
        self.seq = 0

    def reconfigure(self):
        (self.root / "scope.json").write_text(json.dumps(self.cfg))
        if self.ctx is not None:
            self.ctx.store.close()
        self.ctx = Recon(Campaign.load(self.root), log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.ledger = UploadLedger(self.ctx)

    def endpoint(self, path="/api/uploads", method="POST", fields=("file",), extra=None):
        return self.ctx.add_endpoint(f"https://lab.test{path}", "har", method=method,
                                     params=fields, extra=extra)

    def capture(self, aid, method="POST", account="a", role="user", tenant="t1",
                workflow="profile", body=("file",), content_type="multipart/form-data"):
        self.seq += 1
        self.ctx.store.add_observation(
            aid, method, account, {"query": [], "body": list(body), "header": [], "cookie": [],
                                   "ids": {}}, 201, "har", capture_key=f"capture:{self.seq}",
            context={"role": role, "tenant": tenant, "workflow_state": workflow,
                     "csrf_meta": {"content_type": content_type}})

    def sink(self, path="/api/uploads", field="file", method="POST"):
        return next(card for card in self.ledger.plan(limit=100)["sinks"]
                    if card["url"].endswith(path) and card["field"] == field and
                    card["method"] == method)

    def context(self, path="/api/uploads", account="a", role="user", tenant="t1", field="file"):
        card = self.sink(path, field)
        return next(c["context_id"] for c in card["contexts"] if c["basis"] == "captured" and
                    (c["account"], c["role"], c["tenant"]) == (account, role, tenant))

    def baseline(self):
        aid = self.endpoint()
        self.capture(aid)
        self.capture(aid, account="b", tenant="t2")
        return aid, self.context()

    def readiness(self, context_id, case):
        context, sink = self.ledger._context(context_id)
        return self.ledger._readiness(context, sink, case)

    def artifact(self, name, data):
        path = self.root / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return "evidence/" + name

    def response(self, tag="", text='HTTP 201 {"id": "obj-1"}'):
        return f"response={self.artifact('response' + tag, text)}"

    def accept(self, context_id, case="intake-normal", tag="", **extra):
        args = {"channel": "burp", "marker": MARKER, "requests": 1, "bytes_sent": 60,
                "objects": 1, "object_ref": "obj-" + (tag or "1"),
                "facts": ["accepted=yes", "stored=yes"],
                "artifacts": [f"original={self.artifact('orig' + tag, MARKER + ' inert text')}",
                              self.response(tag),
                              f"storage-log={self.artifact('store' + tag, 'stored ' + MARKER)}"],
                "tool_refs": ["burp:history-" + (tag or "1")]}
        args.update(extra)
        return self.ledger.record(context_id, case, "accepted-inert", **args)

    def proof(self, tag, consumer=False):
        items = [self.response(tag),
                 f"effect={self.artifact('effect' + tag, MARKER + ' owned quota effect ' + tag)}",
                 f"replay={self.artifact('replay' + tag, MARKER + ' independent replay ' + tag)}",
                 f"control={self.artifact('control' + tag, CONTROL + ' control denied ' + tag)}"]
        if consumer:
            items.append(f"consumer-log={self.artifact('consumer' + tag, 'consumer job-5 ' + MARKER)}")
        return items


class InventoryTests(Fixture):
    def test_a03_sink_context_identity(self):
        aid = self.endpoint(fields=("file", "avatar"))
        self.endpoint(method="PUT", fields=())
        self.capture(aid, body=("file",))
        self.capture(aid, body=("avatar",))
        self.capture(aid, body=("file",), role="admin")
        self.capture(aid, body=("file",), tenant="t2")
        self.capture(aid, method="PUT", body=(), content_type="application/octet-stream")
        first = self.ledger.sync()
        self.assertEqual((first["sinks_added"], first["contexts_added"]), (3, 5))
        again = self.ledger.sync()
        self.assertEqual((again["sinks_added"], again["contexts_added"]), (0, 0))
        sinks = {(s["field"], s["transport"], s["method"]) for s in self.ledger.plan(limit=100)["sinks"]}
        self.assertEqual(sinks, {("file", "multipart", "POST"), ("avatar", "multipart", "POST"),
                                 ("(body)", "raw-body", "PUT")})
        contexts = self.sink()["contexts"]
        self.assertEqual({(c["role"], c["tenant"]) for c in contexts},
                         {("user", "t1"), ("admin", "t1"), ("user", "t2")})
        self.capture(aid, body=("file",))  # exact duplicate labels: same context
        self.assertEqual(self.ledger.sync()["contexts_added"], 0)
        cid = self.context()
        self.assertEqual(len(next(c for c in self.sink()["contexts"]
                                  if c["context_id"] == cid)["observations"]), 2)
        self.assertEqual(self.ctx.store.request_count(), 0)

    def test_a14_inventory_blind_spots(self):
        self.capture(self.endpoint())
        self.endpoint("/api/uploads/presign", fields=("filename", "content_type"))
        self.endpoint("/api/import/from-url", fields=("source_url",))
        self.ctx.add_endpoint("https://files.storage-provider.example.net/bucket/key", "js")
        plan = self.ledger.plan(limit=100)
        by_path = {card["url"].split("lab.test", 1)[1]: card for card in plan["sinks"]}
        self.assertEqual(by_path["/api/uploads/presign"]["transport"], "signed-storage")
        self.assertEqual(by_path["/api/import/from-url"]["transport"], "url-import")
        self.assertEqual(by_path["/api/import/from-url"]["field"], "source_url")
        for path in ("/api/uploads/presign", "/api/import/from-url"):
            context = by_path[path]["contexts"][0]
            self.assertEqual(context["basis"], "declared")
            self.assertEqual(context["lifecycle"]["events"], [])
            cases = {c["case"]: c for c in context["cases"]}
            ready_case = "signed-storage" if "presign" in path else "url-import"
            self.assertEqual(cases[ready_case]["readiness"], "waiting-capture")
        self.assertEqual([d["value"] for d in plan["out_of_scope_destinations"]],
                         ["https://files.storage-provider.example.net"])
        self.assertFalse(any("storage-provider" in card["url"] for card in plan["sinks"]))
        self.assertEqual((self.ctx.store.request_count(), self.ctx.store.network_attempts()), (0, 0))

    def test_declare_operation_keeps_scope_and_basis(self):
        result = self.ledger.declare("https://lab.test/api/files/finalize", "POST", "(signed-request)",
                                     "signed-storage", "", "Burp history 42: finalize after presigned PUT")
        self.assertFalse(result["executed"])
        self.ledger.sync()
        sinks = [s for s in self.ledger.plan(limit=100)["sinks"] if s["url"].endswith("/finalize")]
        self.assertEqual([(s["transport"], s["basis"]) for s in sinks],
                         [("signed-storage", "operator-declared")])
        with self.assertRaises(OutOfScope):
            self.ledger.declare("https://storage.example.net/put", "PUT", "(body)", "raw-body", "",
                                "seen in Burp")
        with self.assertRaisesRegex(ValueError, "POST, PUT or PATCH"):
            self.ledger.declare("https://lab.test/api/files/finalize", "GET", "(body)", "raw-body",
                                "", "seen in Burp")
        with self.assertRaisesRegex(ValueError, "where it was observed"):
            self.ledger.declare("https://lab.test/api/files/x", "POST", "file", "multipart", "", " ")


class GateTests(Fixture):
    def test_a02_scope_method_and_rules_record(self):
        _, cid = self.baseline()
        self.assertEqual(self.readiness(cid, "intake-normal")[0], "ready")
        for change, needle in ((("program_url", ""), "program_url"),
                               (("rules_reviewed", ""), "rules_reviewed")):
            key, value = change
            saved = self.cfg[key] if key == "program_url" else self.cfg["upload"][key]
            if key == "program_url":
                self.cfg[key] = value
            else:
                self.cfg["upload"][key] = value
            self.reconfigure()
            state, reason = self.readiness(cid, "intake-normal")
            self.assertEqual(state, "blocked")
            self.assertIn(needle, reason)
            with self.assertRaisesRegex(ValueError, needle):
                self.accept(cid)
            if key == "program_url":
                self.cfg[key] = saved
            else:
                self.cfg["upload"][key] = saved
        self.cfg["policy"]["allowed_methods"] = ["GET", "HEAD", "PUT", "PATCH", "DELETE"]
        self.reconfigure()
        self.assertIn("lacks POST", self.readiness(cid, "intake-normal")[1])
        self.cfg["policy"]["allowed_methods"] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
        self.cfg["upload"]["case_grants"] = []
        self.cfg["upload"]["budget"] = {"requests": 0, "per_host": 0, "bytes": 0, "objects": 0}
        self.reconfigure()
        self.assertEqual(self.readiness(cid, "intake-normal"),
                         ("blocked", "upload.budget allows no live traffic"))
        self.assertIn("lacks contrast", self.readiness(cid, "contrast-extension")[1])
        unlabelled = self.endpoint("/api/avatar")
        self.capture(unlabelled, role="", tenant="")
        self.ledger.sync()
        context = next(c for c in self.sink("/api/avatar")["contexts"])
        self.assertEqual(self.readiness(context["context_id"], "intake-normal")[0],
                         "waiting-prerequisite")
        self.assertEqual((self.ctx.store.request_count(), self.ctx.store.network_attempts()), (0, 0))

    def test_review_only_cases_and_lab_channel(self):
        _, cid = self.baseline()
        self.assertEqual(self.readiness(cid, "process-arguments")[0], "review-only")
        with self.assertRaisesRegex(ValueError, "review-only"):
            self.ledger.record(cid, "process-arguments", "attempted", channel="burp",
                               marker=MARKER, requests=1)
        review = f"review={self.artifact('review', 'worker passes display name as one argv item')}"
        with self.assertRaisesRegex(ValueError, "sends nothing"):
            self.ledger.record(cid, "process-arguments", "review-candidate", channel="review",
                               artifacts=[review], requests=1, note="argv review")
        with self.assertRaisesRegex(ValueError, "review artifact"):
            self.ledger.record(cid, "process-arguments", "review-candidate", channel="review",
                               note="argv review")
        with self.assertRaisesRegex(ValueError, "review states"):
            self.ledger.record(cid, "process-arguments", "review-clear", channel="burp",
                               artifacts=[review], note="argv review")
        result = self.ledger.record(cid, "process-arguments", "review-candidate", channel="review",
                                    artifacts=[review], note="Converter receives the display name")
        self.assertEqual(result["state"], "review-candidate")
        self.cfg["in_scope"] = ["lab.test", "app.acme-bounty.com"]
        self.reconfigure()
        live = self.ctx.add_endpoint("https://app.acme-bounty.com/api/uploads", "har",
                                     method="POST", params=["file"])
        self.capture(live)
        self.ledger.sync()
        live_context = next(c["context_id"] for card in self.ledger.plan(limit=100)["sinks"]
                            if "acme-bounty" in card["url"] for c in card["contexts"])
        with self.assertRaisesRegex(ValueError, "lab channel is only for loopback"):
            self.ledger.record(live_context, "intake-normal", "attempted", channel="lab",
                               marker=MARKER, requests=1)

    def test_native_channel_cites_exact_stored_requests(self):
        _, cid = self.baseline()
        upload = self.ctx.store.record_request(
            "POST", "https://lab.test/api/uploads", 201, "manual-test", ["Content-Type"],
            {"content-type": "application/json"}, body=b'{"id": "obj-n"}', body_complete=True,
            basis="target-http", req_body=b"--b\r\n" + MARKER.encode() + b"\r\n--b--\r\n",
            req_content_type="multipart/form-data; boundary=b")
        fetch = self.ctx.store.record_request("GET", "https://lab.test/files/obj-n", 200, "manual-test",
                                              [], {}, body=MARKER.encode(), body_complete=True,
                                              basis="target-http")
        with self.assertRaisesRegex(ValueError, "exact upload operation"):
            self.accept(cid, channel="native", tool_refs=[f"native:{fetch}"])
        with self.assertRaisesRegex(ValueError, "equal the cited"):
            self.accept(cid, channel="native", tool_refs=[f"native:{upload}", f"native:{fetch}"])
        with self.assertRaisesRegex(ValueError, "absent"):
            self.accept(cid, channel="native", tool_refs=["native:999"], requests=1)
        with self.assertRaisesRegex(ValueError, "belong to --channel native"):
            self.accept(cid, tool_refs=[f"native:{upload}"])
        result = self.accept(cid, channel="native", requests=2,
                             tool_refs=[f"native:{upload}", f"native:{fetch}"])
        self.assertEqual(result["requests_declared"], 2)


class EvidenceTests(Fixture):
    def test_a04_accepted_is_not_execution(self):
        _, cid = self.baseline()
        result = self.accept(cid)
        self.assertEqual(result["state"], "accepted-inert")
        self.assertEqual({k: result["facts"][k] for k in ("processed", "executed", "effect")},
                         {"processed": "unknown", "executed": "unknown", "effect": "unknown"})
        self.assertFalse(result["eligible_for_review"])
        self.assertFalse(result["finding_promoted"])
        with self.assertRaisesRegex(ValueError, "only recorded with impact-demonstrated"):
            self.accept(cid, tag="2", facts=["accepted=yes", "executed=yes"])
        with self.assertRaisesRegex(ValueError, "effect=yes"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", channel="burp",
                               marker=MARKER, requests=1, facts=["accepted=yes"],
                               artifacts=[self.response("3")], route="file-upload")

    def test_a05_processing_without_public_url(self):
        _, cid = self.baseline()
        worker = f"worker-log={self.artifact('worker', 'job=j-1 processed ' + MARKER)}"
        result = self.ledger.record(cid, "worker-observation", "accepted-inert", channel="burp",
                                    grant="derivative", marker=MARKER, requests=1, objects=1,
                                    object_ref="tmp-1", facts=["accepted=yes", "processed=yes"],
                                    artifacts=[self.response(), worker])
        self.assertEqual((result["facts"]["processed"], result["facts"]["reachable"],
                          result["facts"]["served"]), ("yes", "unknown", "unknown"))
        self.assertEqual(self.readiness(cid, "derivative-metadata")[0], "ready")
        with self.assertRaisesRegex(ValueError, "processed=yes needs"):
            self.ledger.record(cid, "worker-observation", "accepted-inert", channel="burp",
                               grant="derivative", marker=MARKER, requests=1,
                               facts=["accepted=yes", "processed=yes"],
                               artifacts=[self.response("2"),
                                          f"worker-log={self.artifact('idle', 'queue idle')}"])

    def test_a06_control_and_replay(self):
        _, cid = self.baseline()
        base = {"channel": "burp", "marker": MARKER, "control_marker": CONTROL, "route": "file-upload",
                "requests": 2, "objects": 1, "object_ref": "obj-9",
                "facts": ["accepted=yes", "effect=yes"]}
        missing = [item for item in self.proof("a") if not item.startswith("control=")]
        with self.assertRaisesRegex(ValueError, "effect, replay and control"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", artifacts=missing, **base)
        same = self.proof("b")[:3] + [f"control={self.artifact('replayb', MARKER + ' independent replay b')}"]
        with self.assertRaisesRegex(ValueError, "control must not carry"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", artifacts=same, **base)
        unrelated = self.proof("c")[:3] + [f"control={self.artifact('other', 'some unrelated page')}"]
        with self.assertRaisesRegex(ValueError, "its own control marker"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", artifacts=unrelated, **base)
        with self.assertRaisesRegex(ValueError, "distinct control marker"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", artifacts=self.proof("d"),
                               **{**base, "control_marker": ""})
        result = self.ledger.record(cid, "intake-normal", "impact-demonstrated",
                                    artifacts=self.proof("e"), **base)
        self.assertTrue(result["eligible_for_review"])
        self.assertFalse(result["finding_promoted"])

    def test_a07_a08_layer_attribution(self):
        _, cid = self.baseline()
        blocked = self.response("blk", "HTTP 403 challenge page")
        args = {"channel": "burp", "grant": "contrast", "marker": MARKER, "requests": 1,
                "facts": ["accepted=no"], "response_status": 403,
                "note": "Inert unneeded extension refused"}
        result = self.ledger.record(cid, "contrast-extension", "rejected", artifacts=[blocked], **args)
        self.assertEqual(result["attribution"], "layer-unconfirmed")
        with self.assertRaisesRegex(ValueError, "edge-log"):
            self.ledger.record(cid, "contrast-extension", "rejected", artifacts=[blocked],
                               layer="edge", request_ref="req-77", **args)
        other = f"edge-log={self.artifact('edge-other', 'req-12 action=block')}"
        with self.assertRaisesRegex(ValueError, "request reference"):
            self.ledger.record(cid, "contrast-extension", "rejected", artifacts=[blocked, other],
                               layer="edge", request_ref="req-77", **args)
        edge = f"edge-log={self.artifact('edge', 'req-77 action=block rule=upload-ext')}"
        result = self.ledger.record(cid, "contrast-extension", "rejected", artifacts=[blocked, edge],
                                    layer="edge", request_ref="req-77", **args)
        self.assertEqual((result["attribution"], result["layer"]), ("layer-correlated", "edge"))
        with self.assertRaisesRegex(ValueError, "origin-log"):
            self.ledger.record(cid, "contrast-extension", "rejected", artifacts=[blocked, edge],
                               layer="origin", request_ref="req-77", **args)

    def test_a09_callback_fail_closed(self):
        _, cid = self.baseline()
        attempt = self.ledger.record(cid, "edge-callback", "attempted", channel="burp", marker=MARKER,
                                     requests=1, objects=1, object_ref="obj-c")
        event = attempt["event_id"]
        health = f"receiver-health={self.artifact('health', 'receiver healthy')}"
        log = f"receiver-log={self.artifact('rlog', 'GET /' + MARKER + ' from worker')}"
        host = f"{MARKER}.oob.lab.test"
        good = {"control_marker": CONTROL, "artifacts": [health, log], **TIMES}
        with self.assertRaisesRegex(ValueError, "callback host"):
            self.ledger.callback(event, "http", f"https://{MARKER}.evil.example/x", **good)
        for url in ("https://plain.oob.lab.test/x", "https://bvup_someone_else_00000001.oob.lab.test/x"):
            with self.assertRaisesRegex(ValueError, "bind the attempt marker"):
                self.ledger.callback(event, "http", url, **good)
        with self.assertRaisesRegex(ValueError, "reversed"):
            self.ledger.callback(event, "http", f"https://{host}/x",
                                 **{**good, "observed_at": "2026-11-14T09:59:00Z"})
        with self.assertRaisesRegex(ValueError, "negative-control token is required"):
            self.ledger.callback(event, "http", f"https://{host}/x", **{**good, "control_marker": ""})
        leaked = f"receiver-log={self.artifact('rlog2', MARKER + ' ' + CONTROL)}"
        with self.assertRaisesRegex(ValueError, "negative-control token reached"):
            self.ledger.callback(event, "http", f"https://{host}/x",
                                 **{**good, "artifacts": [health, leaked]})
        with self.assertRaisesRegex(ValueError, "receiver-health"):
            self.ledger.callback(event, "http", f"https://{host}/x", **{**good, "artifacts": [log]})
        late = self.ledger.callback(event, "http", f"https://{host}/x",
                                    **{**good, "observed_at": "2026-11-14T10:30:00Z"})
        self.assertEqual(late["classification"], "inconclusive-late")
        dns = self.ledger.callback(event, "dns", host, **good)
        self.assertEqual(dns["classification"], "resolution-observed")
        self.assertFalse(dns["proves_execution"])
        failed = self.ledger.callback(event, "http", f"https://{host}/x", health="failed",
                                      **{**good, "artifacts": []})
        self.assertEqual((failed["classification"], failed["stopped_host"]),
                         ("receiver-unhealthy", "lab.test"))
        self.cfg["upload"]["case_grants"] = [g for g in GRANTS if g != "callback"]
        self.reconfigure()
        with self.assertRaisesRegex(ValueError, "include callback"):
            self.ledger.callback(event, "dns", host, **good)

    def test_a10_artifact_integrity(self):
        _, cid = self.baseline()
        result = self.accept(cid)
        self.assertTrue(result["retention_deadline"])
        self.assertTrue(self.ledger.verify()["verified"])
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text(MARKER)
        for bad in ("../outside.txt", str(outside)):
            with self.assertRaisesRegex(ValueError, "campaign-relative"):
                self.accept(cid, tag="x", artifacts=[self.response("x"), f"original={bad}"])
        secret = f"response={self.artifact('secret', 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz')}"
        with self.assertRaisesRegex(ValueError, "unredacted secret"):
            self.accept(cid, tag="y", artifacts=[secret])
        stored = self.ctx.store.db.execute("SELECT path FROM upload_artifacts WHERE role='storage-log'"
                                           ).fetchone()["path"]
        (self.root / stored).write_text("tampered")
        integrity = self.ledger.verify()
        self.assertFalse(integrity["verified"])
        self.assertFalse(integrity["artifact_integrity"])
        card = next(c for c in self.sink()["contexts"] if c["context_id"] == cid)
        self.assertEqual(next(x["state"] for x in card["cases"] if x["case"] == "intake-normal"),
                         "stale")

    def test_a11_class_and_chain_dedup(self):
        self.assertEqual([h for h in CHAIN_HINTS if h[0] == "file-upload"],
                         [("file-upload", "xss", "uploaded SVG/HTML served inline -> stored XSS")])
        _, cid = self.baseline()
        base = {"channel": "burp", "marker": MARKER, "control_marker": CONTROL, "requests": 1,
                "objects": 1, "facts": ["accepted=yes", "effect=yes"], "root_key": "quota-root"}
        for tag in ("p", "q"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", route="file-upload",
                               object_ref="obj-" + tag, artifacts=self.proof(tag), **base)
        self.assertEqual(self.ledger.status()["root_groups"], [{"root_key": "quota-root", "events": 2}])
        self.assertEqual(Findings(self.ctx).all(), [])
        with self.assertRaisesRegex(ValueError, "execution route needs executed"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", route="execution",
                               artifacts=self.proof("r"), **base)
        with self.assertRaisesRegex(ValueError, "cross-account routes"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", route="access-control",
                               artifacts=self.proof("s"), **base)
        with self.assertRaisesRegex(ValueError, "xss route needs served=yes"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", route="xss",
                               artifacts=self.proof("t"), **base)

    def test_a12_fixtures_and_skill_stay_inert(self):
        for kind in ("text", "png", "zip"):
            with self.subTest(kind=kind):
                result = self.ledger.fixture(kind)
                data = (self.root / result["path"]).read_bytes()
                control = (self.root / result["control_path"]).read_bytes()
                self.assertEqual(inert_issues(data, kind), [])
                self.assertLessEqual(len(data), 4096)
                self.assertIn(result["marker"].encode(), data)
                self.assertNotIn(result["marker"].encode(), control)
                self.assertIn(result["control_marker"].encode(), control)
        self.assertTrue(inert_issues(b"#!interpreter line\n", "text"))
        self.assertTrue(inert_issues(b"<script>", "text"))
        self.assertTrue(inert_issues(b"a" * 5000, "text"))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("../escape.txt", "x")
        self.assertTrue(any("flat file name" in i for i in inert_issues(buffer.getvalue(), "zip")))
        with self.assertRaisesRegex(ValueError, "4096"):
            self.ledger.fixture("text", 5000)
        with self.assertRaisesRegex(ValueError, "text fixtures only"):
            self.ledger.fixture("png", 10)
        active = re.compile(r"<\?|<%|<script|javascript:|<!ENTITY|/bin/(?:ba)?sh|\bnc\s+-e\b", re.I)
        for path in (SKILLS_DIR / "hunt-file-upload").rglob("*.md"):
            with self.subTest(path=path.name):
                self.assertIsNone(active.search(path.read_text(encoding="utf-8")))

    def test_a13_independent_stage_facts(self):
        _, cid = self.baseline()
        consumed = self.ledger.record(
            cid, "worker-observation", "accepted-inert", channel="burp", grant="derivative",
            marker=MARKER, requests=2, objects=1, object_ref="tmp-13",
            facts=["accepted=yes", "processed=yes", "served=no", "reachable=no"],
            artifacts=[self.response("13"),
                       f"worker-log={self.artifact('w13', 'job=j-13 consumed ' + MARKER)}",
                       f"retrieval={self.artifact('miss13', 'HTTP 404 not found')}"])
        published = self.ledger.record(
            cid, "retrieval-policy", "accepted-inert", channel="burp", marker=MARKER, requests=2,
            facts=["accepted=yes", "stored=yes", "served=yes", "processed=no"],
            artifacts=[self.response("14"),
                       f"retrieval={self.artifact('get14', 'HTTP 200 ' + MARKER)}",
                       f"worker-log={self.artifact('idle14', 'queue idle; no matching job')}"],
            served_headers={"content-type": "text/plain", "content-disposition": "attachment",
                            "x-content-type-options": "nosniff"})
        events = {e["event_id"]: e["facts"] for c in self.sink()["contexts"]
                  if c["context_id"] == cid for e in c["lifecycle"]["events"]}
        first, second = events[consumed["event_id"]], events[published["event_id"]]
        self.assertEqual((first["processed"], first["served"], second["processed"], second["served"]),
                         ("yes", "no", "no", "yes"))
        for facts in (first, second):
            self.assertEqual((facts["accepted"], facts["executed"], facts["effect"]),
                             ("yes", "unknown", "unknown"))
        with self.assertRaisesRegex(ValueError, "Content-Type"):
            self.ledger.record(cid, "retrieval-policy", "accepted-inert", channel="burp", marker=MARKER,
                               requests=1, facts=["accepted=yes", "served=yes"],
                               artifacts=[self.response("15"),
                                          f"retrieval={self.artifact('get15', MARKER)}"])

    def test_execution_needs_consumer_effect_replay_and_control(self):
        _, cid = self.baseline()
        base = {"channel": "burp", "marker": MARKER, "control_marker": CONTROL, "requests": 2,
                "objects": 1, "object_ref": "obj-x"}
        with self.assertRaisesRegex(ValueError, "only recorded with impact-demonstrated"):
            self.ledger.record(cid, "worker-observation", "accepted-inert", grant="derivative",
                               facts=["accepted=yes", "processed=yes", "executed=yes"],
                               artifacts=[self.response("1"), f"worker-log={self.artifact('w', MARKER)}"],
                               **base)
        executed = ["accepted=yes", "effect=yes", "executed=yes"]
        with self.assertRaisesRegex(ValueError, "consumer log"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", route="execution",
                               facts=executed, artifacts=self.proof("2"), **base)
        with self.assertRaisesRegex(ValueError, "execution class"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", route="file-upload",
                               facts=executed, artifacts=self.proof("3", consumer=True), **base)
        with self.assertRaisesRegex(ValueError, "demonstrated effect"):
            self.ledger.record(cid, "intake-normal", "impact-demonstrated", route="execution",
                               facts=["accepted=yes", "executed=yes"],
                               artifacts=self.proof("4", consumer=True), **base)
        result = self.ledger.record(cid, "intake-normal", "impact-demonstrated", route="execution",
                                    facts=executed, artifacts=self.proof("5", consumer=True), **base)
        self.assertEqual((result["facts"]["executed"], result["route"]), ("yes", "execution"))
        self.assertTrue(result["eligible_for_review"])
        self.assertFalse(result["finding_promoted"])


class BudgetStopCleanupTests(Fixture):
    def test_budget_and_stop_rules(self):
        self.cfg["upload"]["budget"] = {"requests": 3, "per_host": 3, "bytes": 500, "objects": 2}
        self.reconfigure()
        _, cid = self.baseline()
        first = self.accept(cid, requests=2)
        with self.assertRaisesRegex(ValueError, "budget exhausted"):
            self.accept(cid, tag="2", requests=2)
        with self.assertRaisesRegex(ValueError, "bytes"):
            self.accept(cid, tag="3", bytes_sent=-1)
        stop = {"channel": "burp", "marker": MARKER, "requests": 1, "note": "Rate limited"}
        with self.assertRaisesRegex(ValueError, "429 is a stop"):
            self.ledger.record(cid, "contrast-format", "blocked", response_status=429, **stop)
        with self.assertRaisesRegex(ValueError, "5xx is a stop"):
            self.ledger.record(cid, "contrast-format", "blocked", response_status=503, **stop)
        blocked = self.ledger.record(cid, "contrast-format", "blocked", response_status=429,
                                     stop_trigger="rate-limit", **stop)
        self.assertEqual(blocked["stopped_host"], "lab.test")
        self.assertIn("stopped", self.readiness(cid, "intake-normal")[1])
        with self.assertRaisesRegex(ValueError, "is stopped"):
            self.accept(cid, tag="4")
        with self.assertRaisesRegex(ValueError, "why it is safe"):
            self.ledger.resume("lab.test", " ")
        cleared = self.ledger.resume("lab.test", "Program window passed; owner notified")
        self.assertEqual(cleared["cleared"], ["rate-limit"])
        self.assertEqual(self.readiness(cid, "intake-normal"),
                         ("blocked", "upload budget exhausted for this host"))
        self.assertEqual(self.ledger.status()["budget"]["used"]["requests"], 3)
        receipt = self.artifact("receipt", "DELETE obj-1 -> 204")
        with self.assertRaisesRegex(ValueError, "receipt"):
            self.ledger.cleanup(first["event_id"], "deleted")
        self.assertTrue(self.ledger.cleanup(first["event_id"], "deleted", receipt, "deleted")["resolved"])
        self.assertEqual(self.ledger.status()["pending_cleanup"], [])

    def test_unresolved_cleanup_blocks_resume_and_overdue_is_reported(self):
        _, cid = self.baseline()
        event = self.accept(cid, object_ref="obj-7")["event_id"]
        failed = self.ledger.cleanup(event, "unverified", note="DELETE returned 200 but object listed")
        self.assertEqual(failed["stopped_host"], "lab.test")
        with self.assertRaisesRegex(ValueError, "resolve the failed cleanup"):
            self.ledger.resume("lab.test", "retry")
        self.ledger.cleanup(event, "deleted", self.artifact("r7", "obj-7 removed"), "second delete")
        self.assertEqual(self.ledger.resume("lab.test", "object confirmed gone")["cleared"],
                         ["cleanup-unresolved"])
        late = self.accept(cid, tag="8", object_ref="obj-8")["event_id"]
        self.ctx.store.db.execute("UPDATE upload_events SET retention_deadline='2020-01-01T00:00:00Z' "
                                  "WHERE id=?", (late,))
        self.ctx.store.db.commit()
        pending = self.ledger.status()["pending_cleanup"]
        self.assertEqual([(p["event"], p["overdue"]) for p in pending], [(late, True)])
        self.ctx.refresh_coverage()
        coverage = next(p for p in write_reports(self.ctx) if p.name == "coverage.md").read_text()
        self.assertIn("## File-upload lifecycle cases", coverage)
        self.assertIn("### Upload objects awaiting cleanup", coverage)


class WiringTests(Fixture):
    def test_cli_report_and_skill_mapping(self):
        self.baseline()
        self.ctx.refresh_coverage()
        self.assertEqual(skills_for("file-upload"), ("hunt-file-upload",))
        for argv in (["upload", "plan", str(self.root), "--limit", "5"],
                     ["upload", "fixture", str(self.root), "--kind", "text"],
                     ["upload", "status", str(self.root)], ["upload", "verify", str(self.root)]):
            out = io.StringIO()
            with self.subTest(argv=argv[:2]), contextlib.redirect_stdout(out):
                self.assertEqual(main(argv), 0)
            self.assertFalse(json.loads(out.getvalue())["executed"])
        coverage = next(p for p in write_reports(self.ctx) if p.name == "coverage.md").read_text()
        rows = [r for r in coverage.splitlines() if "/api/uploads" in r and "| file-upload |" in r]
        self.assertTrue(rows and rows[0].rstrip().endswith("| hunt-file-upload |"))
        self.assertIn("## File-upload lifecycle cases", coverage)

    def test_cases_reference_lists_every_case(self):
        reference = (SKILLS_DIR / "hunt-file-upload" / "references" / "cases.md").read_text()
        self.assertEqual(len(CASES), 24)
        for case, spec in CASES.items():
            self.assertIn(f"| {spec['n']} | `{case}` |", reference)

    def test_config_validation(self):
        self.assertEqual(validate_upload({})["budget"]["requests"], 0)
        validate_upload(scope_template("x", [], "active")["upload"])
        for bad in ({"unknown": 1}, {"case_grants": ["shell"]},
                    {"case_grants": ["contrast"],
                     "budget": {"requests": 5, "per_host": 0, "bytes": 10, "objects": 1}},
                    {"budget": {"requests": 5, "per_host": 6}}, {"rules_reviewed": "2026-13-40"},
                    {"rules_reviewed": "14/11/2026"}, {"retention_days": 0},
                    {"callback_hosts": ["*"]}, {"budget": {"requests": True}}):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                validate_upload(bad)
        self.cfg["upload"]["case_grants"] = ["not-a-grant"]
        with self.assertRaises(ConfigError):
            self.reconfigure()


if __name__ == "__main__":
    unittest.main()
