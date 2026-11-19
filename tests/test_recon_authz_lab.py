"""Owned-loopback authorization surfaces, actual HAR import and offline case proof.

All HTTP goes only to a per-test 127.0.0.1 server. The authz ledger itself sends none.
"""
import http.server
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.authz import AuthzLedger
from recon.campaign import Campaign, scope_template, validate_authz
from recon.har import import_har
from recon.pipeline import Recon

MARKER = "owned_surface_123456789"
NEXT_MARKER = "owned_next_987654321"
OTHER_MARKER = "owned_other_246813579"


class OwnedSurfaceLab(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.batches = 0
        self.form_reads = 0
        lab = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _response(self, status, content):
                raw = json.dumps(content).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                parsed = urlsplit(self.path)
                path, query = parsed.path, parse_qs(parsed.query)
                role = self.headers.get("X-Lab-Role", "user")
                if path == "/api/v2/odata/accounts":
                    if role == "admin" and "$select" in query:
                        return self._response(200, {"marker": MARKER, "actor": role})
                    if role == "user" and "$filter" in query:
                        return self._response(200, {"marker": MARKER, "actor": role,
                                                    "source": "filter"})
                    return self._response(403, {"error": "field denied"})
                if path == "/api/v2/tenant/report":
                    selected = query.get("tenant", [""])[0]
                    if selected not in ("a", "b"):
                        return self._response(400, {"error": "unknown lab tenant"})
                    return self._response(200, {"marker": MARKER if selected == "b" else OTHER_MARKER,
                                                "actor": self.headers.get("X-Lab-Account")})
                if path == "/api/v2/admin/summary":
                    if role == "admin" or self.headers.get("X-HTTP-Method-Override") == "PATCH":
                        return self._response(200, {"marker": MARKER, "actor": role})
                    return self._response(403, {"error": "function denied"})
                if path == "/api/lab/batch-state":
                    return self._response(200, {"marker": MARKER, "batch_reads": lab.batches})
                if path == "/api/lab/form-state":
                    return self._response(200, {"marker": MARKER, "form_reads": lab.form_reads})
                if path in ("/api/v1/reports/list", "/api/v1/reports/export",
                            "/api/v2/reports/export"):
                    if role == "admin" or path == "/api/v1/reports/export":
                        return self._response(200, {"marker": MARKER, "actor": role,
                                                    "surface": path})
                    return self._response(403, {"error": "report denied"})
                if path == "/api/v1/config":
                    if self.headers.get("X-Synthetic-Token") == "owned-lab-token":
                        return self._response(200, {"marker": NEXT_MARKER, "actor": role,
                                                    "result": "test-admin [redacted]"})
                    return self._response(200, {"marker": MARKER, "actor": role,
                                                "token_label": "synthetic [redacted]"})
                return self._response(404, {"error": "not found"})

            def do_POST(self):
                role = self.headers.get("X-Lab-Role", "user")
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                form = self.headers.get("Content-Type") == "application/x-www-form-urlencoded"
                data = parse_qs(raw.decode()) if form else json.loads(raw)
                if self.path == "/api/v2/admin/format":
                    if role == "admin" or form and data.get("mode") == ["summary"]:
                        if form:
                            lab.form_reads += 1
                        return self._response(200, {"marker": MARKER, "actor": role,
                                                    "representation": "form" if form else "json"})
                    return self._response(403, {"error": "representation denied"})
                if self.path == "/graphql":
                    query = data.get("query", "")
                    if role == "admin" or "alias:" in query:
                        return self._response(200, {"marker": MARKER, "actor": role,
                                                    "field": "protected"})
                    return self._response(403, {"error": "field denied"})
                if self.path == "/api/v2/odata/$batch":
                    if data == {"requests": [{"method": "GET", "path": "/api/v2/admin/summary"}]}:
                        lab.batches += 1
                        return self._response(200, {"marker": MARKER, "actor": role,
                                                    "inner": "GET"})
                    return self._response(400, {"error": "unsupported inner operation"})
                return self._response(404, {"error": "not found"})

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.root = Path(self.temp.name) / "campaign"
        self.root.mkdir()
        config = scope_template("owned-surface-lab", [], "active", ["POST", "PATCH"])
        config["in_scope"] = [self.origin]
        config["authz"] = {"probe_grants": ["method-matrix", "representation-fuzz", "write-proof"],
                           "chain_grants": ["token-use"],
                           "probe_budget": {"requests": 60, "per_host": 60}}
        self.config = config
        self.save_config()
        self.ctx = Recon(Campaign.load(self.root), log=lambda _: None)
        self.addCleanup(self.ctx.store.close)
        self.ledger = AuthzLedger(self.ctx)
        self.captures = {}

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def save_config(self):
        (self.root / "scope.json").write_text(json.dumps(self.config))

    def exchange(self, path, role="user", account="low", method="GET", body=None,
                 workflow="review", tenant="a", headers=None, capture=True,
                 mime="application/json", cookie=True):
        data = ((urlencode(body) if mime == "application/x-www-form-urlencoded"
                 else json.dumps(body)).encode() if body is not None else None)
        lab_headers = {"X-Lab-Role": role, "X-Lab-Account": account}
        if cookie:
            lab_headers["Cookie"] = "lab-owned-session=test"
        if body is not None:
            lab_headers["Content-Type"] = mime
        lab_headers.update(headers or {})
        req = Request(self.origin + path, data=data, method=method, headers=lab_headers)
        try:
            with urlopen(req, timeout=2) as response:
                status, content = response.status, response.read().decode()
        except HTTPError as exc:
            status, content = exc.code, exc.read().decode()
        if capture:
            entry = {"request": {"url": self.origin + path, "method": method,
                                 "headers": [{"name": k, "value": v} for k, v in lab_headers.items()]},
                     "response": {"status": status, "content": {
                         "mimeType": "application/json", "text": content}}}
            if body is not None:
                entry["request"]["postData"] = {"mimeType": mime, "text": data.decode()}
            self.captures.setdefault((account, role, tenant, workflow), []).append(entry)
        return status, content

    def import_captures(self):
        for index, ((account, role, tenant, workflow), entries) in enumerate(self.captures.items()):
            path = Path(self.temp.name) / f"capture-{index}.har"
            path.write_text(json.dumps({"log": {"entries": entries}}))
            self.assertEqual(import_har(self.ctx, path, account=account, role=role,
                                        tenant=tenant, workflow_state=workflow)["malformed"], 0)
        self.assertEqual(self.ctx.store.request_count(), 0)
        self.captures.clear()

    def target_context(self, route, method="GET", query_names=(), selector="", role="user"):
        targets = self.ledger.plan(limit=100)["targets"]
        target = next(t for t in targets if urlsplit(t["url"]).path == route and
                      t["method"] == method and t["selector"] == selector and
                      t["query_names"] == list(query_names))
        context = next(c for c in target["contexts"] if c["role"] == role and
                       c["basis"] == "captured")
        return target, context

    def artifacts(self, name, baseline, test, control, before=None, after=None):
        root = self.root / "evidence"
        root.mkdir(exist_ok=True)
        content = {"baseline": baseline, "test": test, "control": control}
        if before is not None:
            content["before"] = before
        if after is not None:
            content["after"] = after
        paths = []
        for role, text in content.items():
            path = root / f"{name}-{role}.txt"
            path.write_text(text)
            paths.append(f"{role}=evidence/{path.name}")
        return paths

    def assert_offline_recorded(self, target, context, case, artifacts, *, variant="default",
                                grant="", impact="none", marker=MARKER,
                                parent_id=None, requests=3, root_key=""):
        result = self.ledger.record(context["context_id"], case, "observed", variant=variant,
                                    grant=grant, marker=marker, parent_id=parent_id,
                                    impact=impact, root_key=root_key, requests=requests,
                                    proof_basis="owned-loopback baseline, test and distinct control",
                                    artifacts=artifacts)
        self.assertFalse(result["executed"])
        self.assertFalse(result["finding_promoted"])
        self.assertTrue(self.ledger.verify()["verified"])
        self.assertEqual(self.ctx.store.request_count(), 0)
        return result

    def test_odata_projection_and_graphql_field_policy(self):
        # The two reads should remain recordable without an opt-in write grant.
        self.config["authz"]["probe_grants"].remove("write-proof")
        self.ctx.campaign.raw = self.config
        self.ledger.grants = validate_authz(self.config["authz"])
        baseline = self.exchange("/api/v2/odata/accounts?$select=protected", role="admin",
                                 account="high")
        test = self.exchange("/api/v2/odata/accounts?$filter=protected", role="user")
        control = self.exchange("/api/v2/odata/accounts?$select=protected", role="user")
        self.assertEqual((baseline[0], test[0], control[0]), (200, 200, 403))
        self.import_captures()
        target, context = self.target_context("/api/v2/odata/accounts", query_names=("$filter",))
        self.assertEqual(target["basis"], "captured")
        self.assertEqual(context["observations"], [self.ctx.store.observations(target["asset_id"])[1]["id"]])
        self.assert_offline_recorded(target, context, "ac-projection",
                                     self.artifacts("odata", baseline[1], test[1], control[1]))

        query = {"query": "query Viewer { viewer { protected } }", "operationName": "Viewer"}
        alias = {"query": "query Viewer { viewer { alias: protected } }", "operationName": "Viewer"}
        baseline = self.exchange("/graphql", role="admin", account="high", method="POST", body=query)
        test = self.exchange("/graphql", role="user", method="POST", body=alias)
        control = self.exchange("/graphql", role="user", method="POST", body=query)
        self.assertEqual((baseline[0], test[0], control[0]), (200, 200, 403))
        self.import_captures()
        target, context = self.target_context("/graphql", method="POST", selector="query Viewer")
        self.assertEqual(next(c["readiness"] for c in context["cases"]
                              if c["case"] == "ac-projection"), "ready")
        # Named GraphQL query over POST is read-only; it does not require a write
        # readback. An untyped/persisted selector remains conservatively write-gated.
        self.assert_offline_recorded(target, context, "ac-projection",
                                     self.artifacts("graphql", baseline[1], test[1], control[1]))

    def test_tenant_function_without_object_reference_swap(self):
        baseline = self.exchange("/api/v2/tenant/report?tenant=b", account="tenant-b", tenant="b")
        test = self.exchange("/api/v2/tenant/report?tenant=b", account="tenant-a", tenant="a")
        control = self.exchange("/api/v2/tenant/report?tenant=a", account="tenant-a", tenant="a")
        self.assertEqual((baseline[0], test[0], control[0]), (200, 200, 200))
        self.assertIn(MARKER, baseline[1])
        self.assertIn(MARKER, test[1])
        self.assertNotIn(MARKER, control[1])
        self.import_captures()
        target, _ = self.target_context("/api/v2/tenant/report", query_names=("tenant",))
        context = next(c for c in target["contexts"] if c["tenant"] == "a")
        self.assertEqual(context["tenant"], "a")
        self.assertEqual(next(c["readiness"] for c in context["cases"]
                              if c["case"] == "ac-tenant"), "ready")
        self.assert_offline_recorded(target, context, "ac-tenant",
                                     self.artifacts("tenant", baseline[1], test[1], control[1]))

    def test_method_override_and_read_only_inner_batch(self):
        baseline = self.exchange("/api/v2/admin/summary", role="admin", account="high")
        test = self.exchange("/api/v2/admin/summary", headers={"X-HTTP-Method-Override": "PATCH"})
        control = self.exchange("/api/v2/admin/summary")
        self.assertEqual((baseline[0], test[0], control[0]), (200, 200, 403))
        self.import_captures()
        target, context = self.target_context("/api/v2/admin/summary")
        with self.assertRaisesRegex(ValueError, "grant"):
            self.ledger.record(context["context_id"], "ac-method", "attempted",
                               variant="matrix:PATCH:header", marker=MARKER, requests=1)
        self.assert_offline_recorded(target, context, "ac-method",
                                     self.artifacts("override", baseline[1], test[1], control[1]),
                                     variant="matrix:PATCH:header", grant="method-matrix")

        before = self.exchange("/api/lab/batch-state", capture=False)[1]
        payload = {"requests": [{"method": "GET", "path": "/api/v2/admin/summary"}]}
        batch = self.exchange("/api/v2/odata/$batch", method="POST", body=payload)
        after = self.exchange("/api/lab/batch-state", capture=False)[1]
        self.assertEqual(batch[0], 200)
        self.assertEqual(json.loads(after)["batch_reads"], json.loads(before)["batch_reads"] + 1)
        self.import_captures()
        target, context = self.target_context("/api/v2/odata/$batch", method="POST")
        self.assert_offline_recorded(target, context, "ac-transport",
                                     self.artifacts("batch", baseline[1], batch[1], control[1],
                                                    before, after), grant="write-proof")

    def test_form_representation_fuzz_is_granted_and_read_back(self):
        baseline = self.exchange("/api/v2/admin/format", role="admin", account="high",
                                 method="POST", body={"mode": "summary"})
        control = self.exchange("/api/v2/admin/format", role="user", method="POST",
                                body={"mode": "summary"})
        before = self.exchange("/api/lab/form-state", capture=False)[1]
        test = self.exchange("/api/v2/admin/format", role="user", method="POST",
                             body={"mode": "summary"}, mime="application/x-www-form-urlencoded")
        after = self.exchange("/api/lab/form-state", capture=False)[1]
        self.assertEqual((baseline[0], control[0], test[0]), (200, 403, 200))
        self.assertEqual(json.loads(after)["form_reads"], json.loads(before)["form_reads"] + 1)
        self.import_captures()
        target, context = self.target_context("/api/v2/admin/format", method="POST")
        context = next(c for c in target["contexts"] if c["role"] == "user" and
                       c["representation"] == "application/x-www-form-urlencoded")
        with self.assertRaisesRegex(ValueError, "grant"):
            self.ledger.record(context["context_id"], "ac-transport", "attempted",
                               variant="fuzz:form", marker=MARKER, requests=1)
        self.assert_offline_recorded(target, context, "ac-transport",
                                     self.artifacts("form", baseline[1], test[1], control[1],
                                                    before, after), variant="fuzz:form",
                                     grant="representation-fuzz")

    def test_version_and_export_sibling_on_owned_data(self):
        baseline = self.exchange("/api/v1/reports/export", role="admin", account="high")
        test = self.exchange("/api/v1/reports/export")
        old_list = self.exchange("/api/v1/reports/list")
        new_export = self.exchange("/api/v2/reports/export")
        self.assertEqual((baseline[0], test[0], old_list[0], new_export[0]),
                         (200, 200, 403, 403))
        self.import_captures()
        for route in ("/api/v1/reports/export", "/api/v1/reports/list",
                      "/api/v2/reports/export"):
            asset = self.ctx.store.find_asset("endpoint", self.origin + route)
            self.ctx.store.update_attrs(asset["id"], {"authz_resource": "reports:owned"})
        target, context = self.target_context("/api/v1/reports/export")
        self.assertEqual(len(target["siblings"]), 2)
        self.assert_offline_recorded(target, context, "ac-version",
                                     self.artifacts("version", baseline[1], test[1], new_export[1]),
                                     root_key="report-policy-gap")
        self.assert_offline_recorded(target, context, "ac-surface",
                                     self.artifacts("surface", baseline[1], test[1], old_list[1]),
                                     root_key="report-policy-gap")
        self.assertEqual(self.ledger.status()["root_groups"][0]["events"], 2)

    def test_synthetic_secret_requires_fresh_granted_chain_event(self):
        baseline = self.exchange("/api/v1/config", role="admin", account="high")
        test = self.exchange("/api/v1/config")
        control = self.exchange("/api/v2/reports/export")
        self.assertEqual((baseline[0], test[0], control[0]), (200, 200, 403))
        self.import_captures()
        target, context = self.target_context("/api/v1/config")
        parent = self.assert_offline_recorded(
            target, context, "ac-role",
            self.artifacts("secret-parent", baseline[1], test[1], control[1]),
            impact="secret")["event_id"]
        follow_baseline = self.exchange("/api/v1/config", role="admin", account="high",
                                        headers={"X-Synthetic-Token": "owned-lab-token"})
        follow_test = self.exchange("/api/v1/config", headers={"X-Synthetic-Token": "owned-lab-token"})
        follow_control = self.exchange("/api/v1/config")
        self.assertEqual((follow_baseline[0], follow_test[0], follow_control[0]), (200, 200, 200))
        self.assertNotIn(NEXT_MARKER, follow_control[1])
        with self.assertRaisesRegex(ValueError, "fresh"):
            self.ledger.record(context["context_id"], "token-use", "observed", grant="token-use",
                               parent_id=parent, marker=MARKER, requests=3,
                               proof_basis="owned lab token read",
                               artifacts=self.artifacts("wrong-marker", baseline[1], test[1], control[1]))
        result = self.assert_offline_recorded(
            target, context, "token-use",
            self.artifacts("secret-child", follow_baseline[1], follow_test[1], follow_control[1]),
            grant="token-use", marker=NEXT_MARKER, parent_id=parent, impact="admin")
        self.assertEqual(self.ledger.status()["chain_rungs"][0]["parent_id"], parent)
        self.assertEqual(result["impact"], "admin")

    def test_anonymous_config_leak_is_distinct_from_a_token_liveness_claim(self):
        baseline = self.exchange("/api/v1/config", role="admin", account="high")
        test = self.exchange("/api/v1/config", role="anonymous", account="anonymous",
                             cookie=False)
        control = self.exchange("/api/v2/reports/export", role="anonymous",
                                account="anonymous", cookie=False)
        self.assertEqual((baseline[0], test[0], control[0]), (200, 200, 403))
        self.import_captures()
        target, context = self.target_context("/api/v1/config", role="anonymous")
        self.assertEqual(context["auth"], "none")
        result = self.assert_offline_recorded(
            target, context, "ac-unauth",
            self.artifacts("anonymous", baseline[1], test[1], control[1]),
            impact="secret")
        self.assertEqual(result["impact"], "secret")
        self.assertEqual(self.ledger.status()["chain_rungs"], [])


if __name__ == "__main__":
    unittest.main()
