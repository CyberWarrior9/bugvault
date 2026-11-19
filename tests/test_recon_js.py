"""Offline JS acquisition/extraction regressions: no target traffic."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from recon import active, extract, sources
from recon.campaign import Campaign, ConfigError
from recon.burp import import_burp
from recon.pipeline import Recon
from recon.jsintel import JsInventory, secret_class
from recon.cli import main
from recon.report import write_reports
from tests.test_recon import write_campaign


class IntegrityTests(unittest.TestCase):
    def test_unsigned_synthetic_jwt_classification_is_offline_only(self):
        def jwt(role):
            enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
            return enc({"alg": "none", "typ": "JWT"}) + "." + enc({"role": role}) + "." + "Z" * 12
        self.assertEqual(secret_class("jwt", jwt("anon")), "public-by-design")
        self.assertEqual(secret_class("jwt", jwt("service_role")), "privileged-looking")
        self.assertEqual(secret_class("aws-access-key-id", "AKIA" + "A" * 16), "ambiguous")

    def test_offline_inventory_evidence_gated_disclosure_and_tamper(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            camp = write_campaign(Path(d) / "camp", "active", [], in_scope=["a.test"])
            ctx = Recon(camp, log=lambda _: None)
            self.addCleanup(ctx.store.close)
            privileged = "sk_live_" + "S" * 24
            body = ('fetch("/api/orders");const public_key="AIza' + 'A' * 35 +
                    '";const private_key="' + privileged + '";').encode()
            rid = ctx.store.record_request("GET", "https://a.test/app.js", 200,
                                           "owned-fixture", [], {}, body=body,
                                           body_complete=True, basis="owned-fixture")
            only_public = ctx.store.record_request("GET", "https://a.test/public.js", 200,
                                                   "owned-fixture", [], {},
                                                   body=('AIza' + 'B' * 35).encode(),
                                                   body_complete=True, basis="owned-fixture")
            missing = ctx.store.record_request("GET", "https://a.test/not-found.js.map", 404,
                                               "owned-fixture", [], {}, body=b"", body_complete=True)
            ledger = JsInventory(ctx)
            self.assertEqual(ledger.sync()["added"], 2)
            self.assertEqual(ledger.sync()["added"], 0)
            rows = {(c["asset_value"], c["bug_class"]) for c in ctx.store.coverage()}
            self.assertIn(("https://a.test/app.js", "info-disclosure"), rows)
            write_reports(ctx)
            self.assertIn("hunt-js-bundle", (camp.root / "coverage.md").read_text())
            self.assertNotIn(("https://a.test/public.js", "info-disclosure"), rows)
            self.assertNotIn(("https://a.test/not-found.js.map", "info-disclosure"), rows)
            self.assertIsNotNone(ctx.store.find_asset("endpoint", "https://a.test/api/orders"))
            self.assertNotIn(privileged, camp.db_path.read_text(errors="replace"))
            facts = ctx.store.db.execute("SELECT predicate FROM response_facts").fetchall()
            self.assertTrue(facts)
            self.assertTrue(all(privileged not in r[0] for r in facts))
            self.assertTrue(ledger.verify()["ok"])
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["js", "status", str(camp.root)]), 0)
            self.assertIn('"complete": false', output.getvalue())
            self.assertNotIn(privileged, output.getvalue())
            ctx.store.db.execute("UPDATE response_capture SET basis='changed' WHERE request_id=?",
                                 (only_public,))
            ctx.store.db.commit()
            self.assertFalse(ledger.verify()["ok"])
            ctx.store.db.execute("UPDATE response_capture SET basis='owned-fixture' WHERE request_id=?",
                                 (only_public,))
            ctx.store.db.commit()
            sha = hashlib.sha256(body).hexdigest()
            (camp.bodies_dir / sha).write_bytes(b"tampered")
            self.assertFalse(ledger.verify()["ok"])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["js", "verify", str(camp.root)]), 2)

    def test_js_config_rejects_unknown_keys_and_caps_and_keeps_probes_off(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "camp"
            camp = write_campaign(root, "active", [], in_scope=["a.test"])
            doc = json.loads((root / "scope.json").read_text())
            for bad in ({"unknown": True}, {"max_map_bytes": 5_000_001},
                        {"probe": {"enabled": True, "budget": 1}},
                        {"probe": {"budget": 100_001}},
                        {"archived_content": True}, {"rules_reviewed": "2026-02-30"}):
                with self.subTest(bad=bad):
                    (root / "scope.json").write_text(json.dumps({**doc, "js": bad}))
                    with self.assertRaises(ConfigError):
                        Campaign.load(root)
            (root / "scope.json").write_text(json.dumps({**doc, "js": {
                "rules_reviewed": "2026-11-15", "archived_content": True,
                "probe": {"enabled": False, "budget": 10}}}))
            self.assertTrue(Campaign.load(root).raw["js"]["archived_content"])

    def test_truncated_map_is_collection_gap_not_bad_json(self):
        with tempfile.TemporaryDirectory() as d:
            camp = write_campaign(Path(d) / "camp", "active", [], in_scope=["a.test"])
            ctx = Recon(camp, log=lambda _: None)
            self.addCleanup(ctx.store.close)
            url = "https://a.test/main.js.map"
            sid = ctx.add("sourcemap", url, source="fixture")
            ctx.client.get = Mock(return_value=Mock(status=200, truncated=True, body=b'{"version":3',
                                                   text=lambda: '{"version":3'))
            active.job_mapparse(ctx, ctx.store.get_asset(sid))
            attrs = ctx.store.get_asset(sid)["attrs"]
            self.assertTrue(attrs["truncated"])
            self.assertNotIn("invalid_json", attrs)
            self.assertTrue(any(f["kind"] == "collection-gap" for f in ctx.store.facts()))

    def test_burp_response_cap_cannot_claim_complete_and_auth_bundle_is_offline(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "camp"
            camp = write_campaign(root, "active", [], in_scope=["a.test"])
            ctx = Recon(camp, log=lambda _: None)
            self.addCleanup(ctx.store.close)
            url = "https://a.test/private/app.js"
            req = b"GET /private/app.js HTTP/1.1\r\nHost: a.test\r\n\r\n"
            resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n" + b"A" * 2_000_001
            item = '<item><url>{}</url><method>GET</method><status>200</status><request base64="true">{}</request><response base64="true">{}</response></item>'.format(
                url, base64.b64encode(req).decode(), base64.b64encode(resp).decode())
            p = root / "burp.xml"
            p.write_text("<items>" + item + "</items>")
            stats = import_burp(ctx, p, "owned-a")
            self.assertEqual(stats["incomplete_responses"], 1)
            self.assertEqual(stats["script_assets"], 1)
            asset = ctx.store.find_asset("js", url)
            self.assertIsNotNone(asset)
            self.assertEqual([j for j in ctx.store.jobs() if j["kind"] == "jsparse"], [])
            response = ctx.store.response(1)
            self.assertEqual(response["body_complete"], 0)
            self.assertEqual(response["context"]["capture_gap"], "import-cap")
            self.assertEqual(response["basis"], "imported-burp-capture")


class ChunkTests(unittest.TestCase):
    def test_webpack5_reconstructs_chunks_not_present_as_strings(self):
        from recon.jschunks import reconstruct
        text = 'n.p="/app/";n.u=e=>"static/js/"+e+"."+{12:"ab12cd34",57:"ff00aa11"}[e]+".chunk.js";'
        got = reconstruct(text, "https://a.test/app/static/js/main.js")
        self.assertEqual({c.url for c in got.chunks}, {
            "https://a.test/app/static/js/12.ab12cd34.chunk.js",
            "https://a.test/app/static/js/57.ff00aa11.chunk.js"})
        self.assertEqual(len(got.composed_only), 2)
        self.assertNotIn("https://a.test/app/static/js/.chunk.js", [c.url for c in got.chunks])

    def test_webpack4_names_and_vite_deps(self):
        from recon.jschunks import reconstruct
        old = ('function jsonpScriptSrc(chunkId){return __webpack_require__.p+"static/js/"+'
               '({0:"main",1:"admin"}[chunkId]||chunkId)+"."+'
               '{0:"abcd1234",1:"defa5678"}[chunkId]+".chunk.js"}')
        got = reconstruct(old, "https://a.test/static/js/runtime.js")
        self.assertEqual({c.path for c in got.chunks}, {
            "static/js/main.abcd1234.chunk.js", "static/js/admin.defa5678.chunk.js"})
        vite = '__vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/admin-A.js","assets/vendor-B.js"])))=>i.map(i=>d[i]);'
        v = reconstruct(vite, "https://a.test/src/main.js")
        self.assertEqual({c.url for c in v.chunks}, {
            "https://a.test/assets/admin-A.js", "https://a.test/assets/vendor-B.js"})

    def test_next_manifest_routes_and_prefix(self):
        from recon.jschunks import reconstruct
        text = 'self.__BUILD_MANIFEST={"/": ["static/chunks/main.js"],"/admin/users": ["static/chunks/pages/admin.js"],"/_app":["static/chunks/webpack.js"]};'
        f = extract.extract_from_js(text)
        self.assertEqual(f.routes, ["/", "/admin/users"])
        self.assertNotIn("/admin/users", [e.raw for e in f.endpoints])
        got = reconstruct(text, "https://a.test/_next/static/build-1/_buildManifest.js")
        self.assertIn("https://a.test/_next/static/chunks/pages/admin.js",
                      [c.url for c in got.chunks])

    def test_federation_remotes_are_inventory_not_new_scope(self):
        from recon.jschunks import reconstruct
        text = 'remotes:{admin:"admin@https://outside.test/remoteEntry.js"}'
        got = reconstruct(text, "https://a.test/static/js/main.js")
        self.assertEqual(got.remotes, ["https://outside.test/remoteEntry.js"])
        self.assertEqual(got.chunks, [])


class ExtractionTests(unittest.TestCase):
    def test_opt_in_archived_bundle_mines_offline_without_replaying_operations(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "camp"
            camp = write_campaign(root, "passive", [], in_scope=["a.test"])
            doc = json.loads((root / "scope.json").read_text())
            doc["js"] = {"rules_reviewed": "2026-11-15", "archived_content": True}
            (root / "scope.json").write_text(json.dumps(doc))
            ctx = Recon(Campaign.load(root), log=lambda _: None)
            self.addCleanup(ctx.store.close)
            domain = ctx.add("domain", "a.test", source="fixture")
            rows = [["original", "timestamp", "statuscode", "mimetype"],
                    ["https://a.test/static/old.js", "20261115123456", "200", "application/javascript"]]
            requests = []
            def passive_get(url, **kw):
                requests.append(url)
                body = json.dumps(rows).encode() if "cdx/search" in url else b'fetch("/api/legacy",{method:"GET"})'
                return Mock(status=200, body=body, truncated=False, request_id=7,
                            text=lambda: body.decode())
            ctx.passive.get = passive_get
            sources.job_wayback(ctx, ctx.store.get_asset(domain))
            self.assertEqual(len(requests), 2)
            self.assertTrue(all(url.startswith("https://web.archive.org/") for url in requests))
            ep = ctx.store.find_asset("endpoint", "https://a.test/api/legacy")
            self.assertIsNotNone(ep)
            self.assertIn("archived", ep["attrs"]["sources"])

    def test_server_action_graphql_permissions_and_client_flow_leads(self):
        code = ('createServerReference("7f3a123456789abc",a.callServer,void 0,a.findSourceMapURL,"deleteUser");'
                'const q=gql`query ReadUser($id: ID!) { user(id:$id) { id name } }`;'
                'const anon=gql`mutation { updateProfile(name:"x") { ok } }`;'
                'const persist={sha256Hash:"' + 'a' * 64 + '"};'
                'const perms=["ADMIN_USERS_EXPORT","billing.refund.approve"];'
                'const taint=new URLSearchParams(location.search).get("q");el.innerHTML=taint;'
                'addEventListener("message",e=>eval(e.data));'
                'target.postMessage(token,"*");'
                'fetch("/api/users/"+params.id);')
        f = extract.extract_from_js(code)
        self.assertEqual(f.server_actions[0]["id"], "7f3a123456789abc")
        self.assertEqual(f.server_actions[0]["name"], "deleteUser")
        self.assertIn("query ReadUser", f.graphql_ops)
        self.assertIn("mutation (anonymous)", f.graphql_ops)
        doc = next(d for d in f.graphql_documents if d["operation"] == "query ReadUser")
        self.assertEqual(doc["variables"], [{"name": "id", "type": "ID!"}])
        self.assertIn("user", doc["top_fields"])
        self.assertIn("ADMIN_USERS_EXPORT", f.perms)
        self.assertIn("billing.refund.approve", f.perms)
        self.assertTrue(any(flow["kind"] == "url-to-html" for flow in f.client_flows))
        self.assertTrue(any(flow["kind"] == "unvalidated-message" for flow in f.client_flows))
        self.assertTrue(any(flow["kind"] == "token-postmessage" for flow in f.client_flows))
        self.assertEqual(f.persisted_hashes, ["a" * 64])

    def test_template_concat_and_client_request_shape(self):
        code = ('const API="/api";const base=window.apiBase;'
                'fetch(`${API}/v2/users/${id}/export`,{method:"POST",body:JSON.stringify({role:r})});'
                'axios.get(`${base}/admin/stats`);const path="/api/users/"+id+"/delete";'
                'const api=axios.create({baseURL:"/api"});'
                'api.interceptors.request.use(c=>{c.headers["X-Tenant-Id"]=t;'
                'c.headers.Authorization="Bearer "+tok;return c});'
                'api.post("/orders",qs.stringify({id:1}),'
                '{headers:{"Content-Type":"application/x-www-form-urlencoded"}});'
                'api.put("/users/me/avatar",new FormData());')
        got = extract.extract_from_js(code)
        by = {e.raw: e for e in got.endpoints}
        self.assertEqual(by["/api/v2/users/{id}/export"].method, "POST")
        self.assertIn("role", by["/api/v2/users/{id}/export"].params)
        self.assertEqual(by["/admin/stats"].method, "GET")
        self.assertTrue(by["/admin/stats"].base_unresolved)
        self.assertIn("/api/users/{id}/delete", by)
        self.assertNotIn("/api", by)
        self.assertNotIn("/orders", by)
        self.assertEqual(by["/api/orders"].transport, "form")
        self.assertEqual(by["/api/users/me/avatar"].transport, "multipart")
        self.assertEqual(by["/api/orders"].headers, ["Authorization", "X-Tenant-Id"])
        self.assertNotIn("Bearer ", repr(by["/api/orders"]))

    def test_real_comment_wins_over_decoy_in_js_string(self):
        from recon.jslex import tokenize
        code = ('const decoy="//# sourceMappingURL=wrong.map";'
                'const reg=/https?:\\/\\/[^/]+/;const nested=`${n ? `x${b}` : c}`;'
                'const commentLookalike="*/"; //# sourceMappingURL=main.js.map\n')
        toks = tokenize(code)
        self.assertIn("template", [t.kind for t in toks])
        self.assertIn("regex", [t.kind for t in toks])
        self.assertEqual(extract.extract_from_js(code).sourcemap, "main.js.map")
        self.assertIsNone(extract.extract_from_js('const decoy="//# sourceMappingURL=no.map";').sourcemap)

    def test_index_maps_ignore_list_root_and_braces_in_values(self):
        sm = {"sections": [{"offset": {"line": 0, "column": 0}, "map": {
            "version": 3, "sourceRoot": "webpack:///src/",
            "sources": ["client.ts", "vendor.ts", None],
            "sourcesContent": ['fetch("/api/live")', 'fetch("/api/vendor")', None],
            "ignoreList": [1]}}]}
        self.assertEqual(extract.sourcemap_sources(sm), [
            ("webpack:///src/client.ts", 'fetch("/api/live")')])
        self.assertEqual(extract._balanced_object('{body:{note:"}"},method:"POST"}', 0),
                         '{body:{note:"}"},method:"POST"}')

    def test_header_precedes_comment_and_collector_queues_only_scoped_chunks(self):
        with tempfile.TemporaryDirectory() as d:
            camp = write_campaign(Path(d) / "camp", "active", [], in_scope=["a.test"])
            ctx = Recon(camp, log=lambda _: None)
            self.addCleanup(ctx.store.close)
            script = "https://a.test/_next/static/b1/main.js"
            sid = ctx.add("js", script, source="fixture", attrs={"page_origin": "https://a.test"})
            code = ('n.u=e=>"static/js/"+e+"."+{12:"ab12cd34"}[e]+".chunk.js";'
                    '//# sourceMappingURL=comment.map\n'
                    'remotes:{admin:"admin@https://outside.test/remoteEntry.js"}')
            ctx.client.get = Mock(return_value=Mock(status=200, body=code.encode(), truncated=False,
                                                   headers={"sourcemap": "header.map"},
                                                   text=lambda: code))
            active.job_jsparse(ctx, ctx.store.get_asset(sid))
            maps = [a["value"] for a in ctx.store.assets("sourcemap")]
            self.assertEqual(maps, ["https://a.test/_next/static/b1/header.map"])
            self.assertIn("https://a.test/_next/static/js/12.ab12cd34.chunk.js",
                          [a["value"] for a in ctx.store.assets("js")])
            self.assertEqual(ctx.store.get_asset(sid)["attrs"]["composed_only"], 1)
            self.assertTrue(any("federation remote outside" in f["summary"]
                                for f in ctx.store.facts()))
            self.assertFalse(any("outside.test" in a["value"]
                                 for a in ctx.store.assets("js")))

    def test_ws_is_an_endpoint_bare_hostname_intel_and_csrf_hint_is_static(self):
        from recon.csrf import CsrfLedger
        with tempfile.TemporaryDirectory() as d:
            camp = write_campaign(Path(d) / "camp", "active", [],
                                  in_scope=["a.test", "rt.a.test"])
            ctx = Recon(camp, log=lambda _: None)
            self.addCleanup(ctx.store.close)
            sid = ctx.add("js", "https://a.test/main.js", source="fixture")
            active._process_js_text(ctx,
                'const ws="wss://rt.a.test/socket";const h="api-staging.other.test";'
                'fetch("/api/save",{method:"POST",body:JSON.stringify({name:n})});',
                "https://a.test/main.js", "https://a.test", "js", sid, 0)
            self.assertIsNotNone(ctx.store.find_asset("endpoint", "wss://rt.a.test/socket"))
            self.assertIn("api-staging.other.test", [a["value"] for a in ctx.store.assets("intel")])
            op = next(o for o in ctx.store.operations() if o["endpoint"] == "https://a.test/api/save")
            self.assertEqual(op["attrs"]["static_content_types"], ["application/json"])
            led = CsrfLedger(ctx)
            led.sync()
            action = next(a for a in led.plan(limit=500)["actions"] if a["route"] == "/api/save")
            self.assertTrue(any("static-reference" in c["metadata_basis"]
                                for c in action["contexts"]))

    def test_secret_in_url_path_is_withheld_from_endpoint_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            camp = write_campaign(Path(d) / "camp", "active", [], in_scope=["a.test"])
            ctx = Recon(camp, log=lambda _: None)
            self.addCleanup(ctx.store.close)
            sid = ctx.add("js", "https://a.test/main.js", source="fixture")
            secret = "sk_live_" + "V" * 24
            active._process_js_text(ctx, 'fetch("/api/token/' + secret + '")',
                                    "https://a.test/main.js", "https://a.test", "js", sid, 0)
            self.assertFalse(any(secret in e["value"] for e in ctx.store.assets("endpoint")))
            self.assertTrue(any(f["kind"] == "collection-gap" for f in ctx.store.facts()))


if __name__ == "__main__":
    unittest.main()
