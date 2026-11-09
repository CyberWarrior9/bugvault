import http.server
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.campaign import Campaign, ConfigError, OutOfScope, PolicyViolation, Scope
from recon import extract
from recon.har import import_har
from recon.net import PassiveClient
from recon.pipeline import Recon
from recon.report import idor_candidates, param_matrix, write_reports
from recon.runtime import decide, default_mock, route_targets
from recon.score import applicable_classes, freshness, version_index
from recon.store import Store

FAKE_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
MAIN_JS = """
const api = { list: (id) => fetch("/api/v2/users/", {method:"POST", body: JSON.stringify({email: e, role: r})}) };
axios.get(`/api/v2/orders/${orderId}`, {params:{page:1, include_deleted:true}});
const routes = [{path:"/settings/billing", component: B}, {path:"/admin/users/:id", component: U}];
const perms = ["user:delete", "billing:refund:approve"];
navigator.sendBeacon("https://analytics.thirdparty.example/collect");
const lazy = () => import("static/js/settings.chunk.js");
const k = "%s";
const q = gql`query GetViewer { viewer { id } }`;
//# sourceMappingURL=main.abc123.js.map
""" % FAKE_AWS_KEY
CHUNK_JS = 'fetch("/api/v2/settings/export?format=csv&url=" + u)'
SOURCEMAP = {
    "version": 3,
    "sources": ["webpack:///src/api/admin.ts", "webpack:///node_modules/x/index.js"],
    "sourcesContent": ["export const purge = () => request('/api/internal/cache/purge', "
                       "{method: 'POST'})", "fetch('/api/should-not-appear')"],
}


def make_lab(root: Path, port_holder: dict) -> None:
    (root / "static" / "js").mkdir(parents=True)
    (root / "index.html").write_text(
        '<html><head><title>Lab App</title></head><body><div id="root"></div>'
        '<script src="/static/js/main.abc123.js"></script>'
        '<a href="/about">About</a><a href="https://elsewhere.example/x">x</a>'
        '<form action="/search" method="get"><input name="q"></form></body></html>')
    (root / "static/js/main.abc123.js").write_text(MAIN_JS)
    (root / "static/js/settings.chunk.js").write_text(CHUNK_JS)
    (root / "static/js/main.abc123.js.map").write_text(json.dumps(SOURCEMAP))
    (root / "robots.txt").write_text("User-agent: *\nDisallow: /internal-admin/\n"
                                     "Sitemap: /sitemap.xml\n")
    port_holder["sitemap"] = root / "sitemap.xml"


class LabServer:
    def __init__(self, root: Path):
        self.hits = []
        lab = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=str(root), **k)

            def do_GET(self):
                lab.hits.append(self.path)
                if self.path == "/go":
                    self.send_response(302)
                    self.send_header("Location", "https://evil.example.invalid/x")
                    self.end_headers()
                    return
                return super().do_GET()

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def write_campaign(root: Path, mode: str, seeds, in_scope=("127.0.0.1",), out=("/logout",),
                   runtime=None) -> Campaign:
    root.mkdir(parents=True, exist_ok=True)
    (root / "scope.json").write_text(json.dumps({
        "program": "lab", "seeds": list(seeds), "in_scope": list(in_scope),
        "out_of_scope": list(out), "runtime": runtime or {},
        "policy": {"mode": mode, "max_rps": 50, "user_agent": "bugvault-test"}}))
    return Campaign.load(root)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.s = Scope.from_lists(
            ["*.acme.com", "acme.com", "https://partner.io/acme/", "10.0.0.0/24", "api.acme.io"],
            ["blog.acme.com", "/logout", "*.cdn.acme.com"])

    def test_in(self):
        for u in ["https://acme.com/", "https://a.b.acme.com/x", "http://10.0.0.7:8080/",
                  "https://partner.io/acme/x", "https://API.ACME.IO./v1", "wss://x.acme.com/ws"]:
            self.assertTrue(self.s.is_in(u), u)

    def test_out(self):
        for u in ["https://evilacme.com/", "https://acme.com.evil.net/", "https://blog.acme.com/",
                  "https://img.cdn.acme.com/a", "https://partner.io/other",
                  "https://partner.io/acme/../admin", "http://10.0.1.1/", "ftp://acme.com/",
                  "https://acme.com/logout", "https://acme.com/LOGOUT/", "https://acme.com/a/../logout",
                  "https://acme.com/%6cogout", "https://acme.com/%256cogout", "javascript:alert(1)",
                  "https://user@evil.com/", "http://[::1]/"]:
            self.assertFalse(self.s.is_in(u), u)

    def test_wildcard_is_not_apex(self):
        s = Scope.from_lists(["*.acme.com"], [])
        self.assertFalse(s.is_in("https://acme.com/"))

    def test_bad_rules(self):
        for bad in ["*", "*acme.com", "/", ""]:
            with self.assertRaises(ConfigError):
                Scope.from_lists([bad] if bad != "/" else ["acme.com"], ["/"] if bad == "/" else [])

    def test_seed_must_be_in_scope(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ConfigError):
                write_campaign(Path(d) / "c", "passive", ["https://other.example/"])


class ExtractTests(unittest.TestCase):
    def test_template_and_key(self):
        self.assertEqual(extract.template_path("/api/users/123/orders/${oid}/"),
                         "/api/users/{id}/orders/{id}")
        self.assertEqual(extract.template_path("/u/:userId/x"), "/u/{id}/x")
        self.assertEqual(extract.endpoint_key("https://a.com:443/v1/x/550e8400-e29b-41d4-a716-446655440000?y=1"),
                         "https://a.com/v1/x/{id}")
        self.assertEqual(extract.origin_of("http://127.0.0.1:8080/x"), "http://127.0.0.1:8080")

    def test_js(self):
        f = extract.extract_from_js(MAIN_JS)
        by = {e.raw: e for e in f.endpoints}
        self.assertEqual(by["/api/v2/users/"].method, "POST")
        self.assertEqual(by["/api/v2/users/"].params, ["email", "role"])
        orders = by["/api/v2/orders/${orderId}"]
        self.assertEqual(orders.method, "GET")
        self.assertEqual(orders.params, ["page", "include_deleted"])
        self.assertIn("https://analytics.thirdparty.example/collect", by)
        self.assertIn("/settings/billing", f.routes)
        self.assertIn("/admin/users/:id", f.routes)
        self.assertEqual(f.perms, ["user:delete", "billing:refund:approve"])
        self.assertEqual(f.sourcemap, "main.abc123.js.map")
        self.assertIn("static/js/settings.chunk.js", f.chunks)
        self.assertIn("query GetViewer", f.graphql_ops)
        self.assertEqual(len(f.secrets), 1)
        self.assertNotIn(FAKE_AWS_KEY, f.secrets[0][1])

    def test_routes_are_not_endpoints_and_methods_do_not_leak(self):
        f = extract.extract_from_js(MAIN_JS)
        raws = {e.raw for e in f.endpoints}
        self.assertNotIn("/settings/billing", raws)
        self.assertNotIn("/admin/users/:id", raws)
        g = extract.extract_from_js(
            'fetch("/api/a",{method:"DELETE"});x();y();z();fetch("/api/b");'
            'axios({method:"put",url:"/api/c",data:{name:n}});'
            'router.push("/dash/home");')
        by = {e.raw: e for e in g.endpoints}
        self.assertEqual(by["/api/a"].method, "DELETE")
        self.assertIsNone(by["/api/b"].method)
        self.assertEqual(by["/api/c"].method, "PUT")
        self.assertNotIn("/dash/home", by)
        self.assertIn("/dash/home", g.routes)

    def test_noise_rejected(self):
        f = extract.extract_from_js('a="/"; b="/a"; c="/12/34"; d="text/html"; e="/img/x.png"; '
                                    'g="//"; h="/MM/dd/yyyy"')
        self.assertEqual(f.endpoints, [])

    def test_robots(self):
        paths, maps = extract.parse_robots("User-agent: *\nDisallow: /admin/*.php\n"
                                           "Allow: /pub$\nSitemap: https://a.com/s.xml\n")
        self.assertEqual(paths, ["/admin/", "/pub"])
        self.assertEqual(maps, ["https://a.com/s.xml"])


class ScoreTests(unittest.TestCase):
    def ep(self, url, **attrs):
        return {"id": 1, "value": url, "attrs": attrs}

    def test_freshness_orders_hidden_above_linked(self):
        hidden = self.ep("https://a.com/api/v1/admin/export", sources=["sourcemap"],
                         params=["user_id"], api_like=True)
        linked = self.ep("https://a.com/about", sources=["html"])
        newer = self.ep("https://a.com/api/v2/admin/export", sources=["js"])
        vidx = version_index([hidden, linked, newer])
        sh, why = freshness(hidden, vidx)
        sl, _ = freshness(linked, vidx)
        self.assertGreater(sh, sl)
        self.assertTrue(any("older API version" in w for w in why))

    def test_classes(self):
        c = applicable_classes(self.ep("https://a.com/api/orders/{id}/refund", methods=["POST"],
                                       params=["callback_url", "amount"]))
        for cls in ("idor-bola", "ssrf", "csrf", "mass-assignment", "race-conditions"):
            self.assertIn(cls, c)
        listing = applicable_classes(self.ep("https://a.com/api/orders", methods=["GET"],
                                             params=["page"]))
        self.assertNotIn("file-read", listing)
        self.assertNotIn("race-conditions", listing)


class RuntimeDecisionTests(unittest.TestCase):
    def d(self, url, method="GET", rtype="xhr", in_scope=True, live=False, nav=False, req=()):
        return decide(url, method, rtype, in_scope=in_scope, requested_docs=set(req),
                      live_api=live, is_nav=nav)

    def test_rules(self):
        self.assertEqual(self.d("https://a.com/api/x", in_scope=False), "abort-scope")
        self.assertEqual(self.d("https://a.com/api/x", "POST"), "mock")
        self.assertEqual(self.d("https://a.com/api/x", "POST", live=True), "mock")
        self.assertEqual(self.d("https://a.com/api/x", "GET", live=True), "live")
        self.assertEqual(self.d("https://a.com/form", "POST", "document"), "abort-write")
        self.assertEqual(self.d("https://a.com/delete?id=1", "GET", "document", nav=True),
                         "abort-nav")
        self.assertEqual(self.d("https://a.com/", "GET", "document", nav=True,
                                req=["https://a.com/"]), "continue")
        self.assertEqual(self.d("https://a.com/app.js", "GET", "script"), "continue")

    def test_mock_and_routes(self):
        m = default_mock(["user:delete"])
        self.assertIn("user:delete", m["data"]["permissions"])
        self.assertEqual(route_targets("https://a.com", ["/u/:id", "/x/*"], True, 10),
                         ["https://a.com/#/u/1", "https://a.com/#/x/1"])


class LabPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        holder = {}
        make_lab(self.root / "site", holder)
        self.lab = LabServer(self.root / "site").__enter__()
        holder["sitemap"].write_text(
            f"<urlset><url><loc>http://127.0.0.1:{self.lab.port}/pricing</loc></url></urlset>")
        self.base = f"http://127.0.0.1:{self.lab.port}"

    def tearDown(self):
        self.lab.__exit__()
        self.tmp.cleanup()

    def test_passive_mode_never_touches_target(self):
        camp = write_campaign(self.root / "camp", "passive", [self.base + "/"])
        ctx = Recon(camp, log=lambda m: None)
        stats = ctx.run()
        self.assertEqual(self.lab.hits, [])
        self.assertEqual(ctx.store.request_count(), 0)
        self.assertGreater(stats["skipped"], 0)
        notes = {j["note"] for j in ctx.store.jobs() if j["state"] == "skipped"}
        self.assertTrue(all("policy" in n for n in notes), notes)

    def test_redirect_out_of_scope_not_followed(self):
        camp = write_campaign(self.root / "camp", "active", [self.base + "/"])
        ctx = Recon(camp, log=lambda m: None)
        r = ctx.client.get(self.base + "/go", purpose="test")
        self.assertEqual(r.status, 302)
        self.assertEqual(r.blocked_redirect, "https://evil.example.invalid/x")
        with self.assertRaises(OutOfScope):
            ctx.client.get(self.base + "/logout", purpose="test")
        with self.assertRaises(PolicyViolation):
            ctx.client.get(self.base + "/", purpose="test", method="POST")

    def test_passive_client_refuses_target_and_unknown_hosts(self):
        camp = write_campaign(self.root / "camp", "active", [self.base + "/"])
        ctx = Recon(camp, log=lambda m: None)
        with self.assertRaises(PolicyViolation):
            ctx.passive.get(self.base + "/", purpose="test")
        with self.assertRaises(PolicyViolation):
            ctx.passive.get("https://evil.example/", purpose="test")

    def test_active_harvest_end_to_end(self):
        camp = write_campaign(self.root / "camp", "active", [self.base + "/"])
        ctx = Recon(camp, log=lambda m: None)
        stats = ctx.run()
        eps = {e["value"][len(self.base):]: e for e in ctx.store.assets("endpoint", in_scope=True)}
        users = eps["/api/v2/users"]["attrs"]
        self.assertEqual(users["methods"], ["POST"])
        self.assertEqual(users["params"], ["email", "role"])
        self.assertEqual(eps["/api/v2/orders/{id}"]["attrs"]["params"], ["page", "include_deleted"])
        self.assertIn("url", eps["/api/v2/settings/export"]["attrs"]["params"])
        self.assertEqual(eps["/api/internal/cache/purge"]["attrs"]["sources"], ["sourcemap"])
        self.assertNotIn("/api/should-not-appear", eps)
        self.assertIn("robots", eps["/internal-admin"]["attrs"]["sources"])
        self.assertIn("sitemap", eps["/pricing"]["attrs"]["sources"])
        self.assertEqual(eps["/search"]["attrs"]["params"], ["q"])
        self.assertEqual(eps["/api/v1/users"]["attrs"]["sources"], ["version-sibling"])
        self.assertNotIn("/api/v1/users", self.lab.hits)
        routes = {r["value"] for r in ctx.store.assets("route")}
        self.assertIn(self.base + "/settings/billing", routes)
        intel = {a["value"] for a in ctx.store.assets("intel")}
        self.assertIn("https://analytics.thirdparty.example", intel)
        self.assertIn("https://elsewhere.example", intel)
        kinds = {f["kind"] for f in ctx.store.facts()}
        self.assertTrue({"secret-lead", "sourcemap"} <= kinds, kinds)
        svc = ctx.store.find_asset("service", self.base)["attrs"]
        self.assertTrue(svc["spa"])
        self.assertIn("billing:refund:approve", svc["perm_candidates"])
        # every request went to the lab, and the raw secret is stored nowhere in the DB
        db = sqlite3.connect(str(camp.db_path))
        hosts = {u.split("/")[2] for (u,) in db.execute("SELECT url FROM requests")}
        self.assertEqual(hosts, {f"127.0.0.1:{self.lab.port}"})
        dump = "\n".join(db.iterdump())
        self.assertNotIn(FAKE_AWS_KEY, dump)
        # coverage seeded for real endpoints, not for inferred siblings
        cov = {(c["asset_value"][len(self.base):], c["bug_class"]) for c in ctx.store.coverage()}
        self.assertIn(("/api/v2/users", "mass-assignment"), cov)
        self.assertIn(("/api/v2/settings/export", "ssrf"), cov)
        self.assertFalse(any(v == "/api/v1/users" for v, _ in cov))
        runtime_jobs = [j for j in ctx.store.jobs() if j["kind"] == "runtime"]
        self.assertEqual(len(runtime_jobs), 1)
        self.assertIn(runtime_jobs[0]["state"], ("done", "skipped"))
        self.assertEqual(stats["failed"], 0, [j for j in ctx.store.jobs() if j["state"] == "failed"])
        paths = write_reports(ctx)
        recon_md = paths[0].read_text()
        self.assertIn("/api/internal/cache/purge", recon_md)
        self.assertIn("Old-version candidates", recon_md)
        # resumable: a second run sends no new requests
        before = ctx.store.request_count()
        ctx.run()
        self.assertEqual(ctx.store.request_count(), before)


class HarTests(unittest.TestCase):
    def har(self, user_id, order_id, extra_param=None):
        body = {"note": "x", "items": [1]}
        if extra_param:
            body[extra_param] = 1
        return {"log": {"entries": [
            {"request": {"method": "POST", "url": f"https://app.acme.com/api/orders/{order_id}/pay",
                         "headers": [{"name": "Cookie", "value": "session=SUPERSECRET"}],
                         "queryString": [{"name": "user_id", "value": str(user_id)}],
                         "postData": {"mimeType": "application/json", "text": json.dumps(body)}},
             "response": {"status": 200, "content": {"mimeType": "application/json"}}},
            {"request": {"method": "GET", "url": "https://cdn.other.net/x.png", "headers": []},
             "response": {"status": 200, "content": {"mimeType": "image/png"}}},
        ]}}

    def test_two_accounts(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            camp = write_campaign(root / "camp", "passive", ["acme.com"],
                                  in_scope=["acme.com", "*.acme.com"])
            ctx = Recon(camp, log=lambda m: None)
            for acct, uid, oid, extra in (("alice", 11, 501, "coupon"), ("bob", 22, 502, None)):
                p = root / f"{acct}.har"
                p.write_text(json.dumps(self.har(uid, oid, extra)))
                import_har(ctx, p, acct)
            ep = ctx.store.find_asset("endpoint", "https://app.acme.com/api/orders/{id}/pay")
            self.assertTrue(ep["attrs"]["auth_seen"])
            self.assertEqual(sorted(ep["attrs"]["accounts"]), ["alice", "bob"])
            idor = idor_candidates(ctx.store)
            self.assertEqual(len(idor), 1)
            self.assertIn("user_id", idor[0][4])
            self.assertIn("path[3]", idor[0][4])
            pm = param_matrix(ctx.store)[0]
            self.assertIn("note", pm[4])
            self.assertEqual(pm[5], ["coupon"])
            dump = "\n".join(sqlite3.connect(str(camp.db_path)).iterdump())
            self.assertNotIn("SUPERSECRET", dump)
            self.assertIn("https://cdn.other.net", {a["value"] for a in ctx.store.assets("intel")})


if __name__ == "__main__":
    unittest.main()
