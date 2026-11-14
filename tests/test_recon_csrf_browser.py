"""Owned-loopback two-origin CSRF lab in real Chromium, feeding the CSRF ledger.

Three lab hostnames resolve to one 127.0.0.1 server through Chromium's host-resolver
rules (every other hostname is forced to fail, so nothing leaves the machine):

    app.example.com       the target application
    sibling.example.com   a same-site sibling initiator (same site, different origin)
    attacker.example.net  a cross-site initiator

The lab checks the browser mechanics the ledger's case families rely on, then records
the real outcomes through `CsrfLedger` and checks its verdicts. Skipped without
Playwright/Chromium:

    .venv/bin/python -m unittest tests.test_recon_csrf_browser
"""
import http.server
import json
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from playwright.sync_api import Error as PlaywrightError, sync_playwright
    HAVE_PLAYWRIGHT = True
except ImportError:
    HAVE_PLAYWRIGHT = False

from recon.csrf import CsrfLedger
from recon.csrfmeta import request_meta
from recon.pipeline import Recon
from tests.test_recon import write_campaign

APP, SIBLING, ATTACKER = "app.example.com", "sibling.example.com", "attacker.example.net"


class CsrfLab:
    """Deliberately mixed defenses on one target; initiator pages set by the test."""

    def __init__(self):
        self.lock = threading.Lock()
        self.sessions, self.pages, self.log, self.set_cookies = {}, {}, [], []
        lab = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body, ctype="text/html", headers=()):
                data = body.encode() if isinstance(body, str) else body
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _handle(self):
                host = (self.headers.get("Host") or "").split(":")[0]
                url = urlsplit(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                cookies = dict(p.strip().split("=", 1) for p in
                               (self.headers.get("Cookie") or "").split(";") if "=" in p)
                with lab.lock:
                    session = lab.sessions.get(cookies.get("sid"))
                    lab.log.append({"host": host, "method": self.command, "path": url.path,
                                    "cookie_attached": session is not None,
                                    "origin": self.headers.get("Origin"),
                                    "content_type": self.headers.get("Content-Type"),
                                    "headers": [(k, v) for k, v in self.headers.items()],
                                    "body": body.decode("latin-1")})
                    page = lab.pages.get((host, url.path))
                    if page is not None:
                        return self._send(200, page)
                    if host != APP:
                        return self._send(404, "no page")
                    return lab.app(self, url, body, session)

            do_GET = do_POST = do_OPTIONS = _handle

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def origin(self, host):
        return f"http://{host}:{self.port}"

    def app(self, h, url, body, session):
        path, query = url.path, parse_qs(url.query)
        if path == "/login":
            sid, mode = secrets.token_hex(8), query.get("samesite", ["lax"])[0]
            self.sessions[sid] = {"email": "v@lab.example", "deleted": 0, "profile": "initial",
                                  "admin": 0, "token": secrets.token_hex(8)}
            attr = {"lax": "; SameSite=Lax", "strict": "; SameSite=Strict", "omit": ""}[mode]
            cookie = f"sid={sid}; Path=/; HttpOnly{attr}"
            self.set_cookies.append((mode, cookie))
            return h._send(200, "signed in", headers=[("Set-Cookie", cookie)])
        if path == "/state":
            return h._send(200, json.dumps({k: v for k, v in (session or {}).items() if k != "token"}
                                           if session else {"error": "no session"}), "application/json")
        if path == "/email" and h.command == "POST":
            if not session:  # 200 error envelope: status alone says nothing about state
                return h._send(200, "error: not signed in")
            session["email"] = parse_qs(body.decode())["email"][0]
            return h._send(200, "saved")
        if path == "/email-token" and h.command == "POST":
            form = parse_qs(body.decode())
            if not session or form.get("csrf", [""])[0] != session["token"]:
                return h._send(200, "error: invalid request")
            session["email"] = form["email"][0]
            return h._send(200, "saved")
        if path == "/delete-item":  # state-changing GET
            if session:
                session["deleted"] += 1
            return h._send(200, "deleted" if session else "error: not signed in")
        if path in ("/api/profile", "/api/profile-strict") and h.command == "POST":
            if path.endswith("-strict") and (h.headers.get("Content-Type") or "") != "application/json":
                return h._send(415, '{"error":"json only"}', "application/json")
            data = json.loads(body.decode().strip())  # lenient: ignores Content-Type
            if session:
                session["profile"] = data["profile"]
            return h._send(200, '{"ok":true}', "application/json")  # no CORS headers
        if path == "/api/admin":
            if h.command == "OPTIONS":
                return h._send(403, "preflight refused")  # no Access-Control-Allow-*
            if session and h.headers.get("X-CSRF") == "1":
                session["admin"] += 1
            return h._send(200, '{"ok":true}', "application/json")
        return h._send(404, "not found")

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def form(action, fields, enctype=None):
    inputs = "".join(f"<input name='{n}' value='{v}'>" for n, v in fields)
    enc = f" enctype='{enctype}'" if enctype else ""
    return f"<html><body><form id='f' method='post' action='{action}'{enc}>{inputs}</form></body></html>"


@unittest.skipUnless(HAVE_PLAYWRIGHT, "playwright not installed")
class CsrfBrowserLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = CsrfLab().__enter__()
        cls.pw = sync_playwright().start()
        rules = ("MAP *.example.com 127.0.0.1, MAP *.example.net 127.0.0.1, MAP * ~NOTFOUND")
        try:
            cls.browser = cls.pw.chromium.launch(args=[
                f"--host-resolver-rules={rules}", "--no-proxy-server",
                "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable"])
        except PlaywrightError as exc:
            cls.pw.stop()
            cls.lab.__exit__()
            raise unittest.SkipTest(f"chromium unavailable: {exc}")
        cls.build = f"Chromium {cls.browser.version} (Playwright, headless)"

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.lab.__exit__()

    # ---------------- browser helpers
    def victim(self, samesite):
        context = self.browser.new_context()
        self.addCleanup(context.close)
        page = context.new_page()
        page.set_default_timeout(15000)
        page.goto(self.lab.origin(APP) + f"/login?samesite={samesite}")
        return page

    def state(self, page):
        page.goto(self.lab.origin(APP) + "/state")
        return json.loads(page.evaluate("document.body.innerText"))

    def submit_from(self, page, host, html, path="/poc"):
        self.lab.pages[(host, path)] = html
        page.goto(self.lab.origin(host) + path)
        mark = len(self.lab.log)
        with page.expect_navigation():
            page.evaluate("document.getElementById('f').submit()")
        return [e for e in self.lab.log[mark:] if e["host"] == APP]

    def script_from(self, page, host, js):
        self.lab.pages[(host, "/script")] = "<html><body>initiator</body></html>"
        page.goto(self.lab.origin(host) + "/script")
        mark = len(self.lab.log)
        result = page.evaluate(js)
        return result, [e for e in self.lab.log[mark:] if e["host"] == APP]

    def navigate_from(self, page, host, target):
        self.lab.pages[(host, "/nav")] = "<html><body>nav</body></html>"
        page.goto(self.lab.origin(host) + "/nav")
        mark = len(self.lab.log)
        with page.expect_navigation():
            page.evaluate(f"location.href = {json.dumps(target)}")
        return [e for e in self.lab.log[mark:] if e["host"] == APP]

    # ---------------- the lab
    def test_browser_mechanics_and_ledger_verdicts(self):
        app = self.lab.origin(APP)
        sib, att = self.lab.origin(SIBLING), self.lab.origin(ATTACKER)
        results = {}

        # --- SameSite=Lax victim
        page = self.victim("lax")
        before = self.state(page)
        # legitimate same-origin baseline from the app's own page
        legit = self.submit_from(page, APP, form("/email", [("email", "legit@lab.example")]),
                                 path="/settings")
        baseline_after = self.state(page)
        self.assertEqual(baseline_after["email"], "legit@lab.example")
        results["baseline"] = (before, baseline_after, legit[-1])

        # cross-site top-level POST: Lax cookie withheld; 200 error envelope, no change
        b = self.state(page)
        sent = self.submit_from(page, ATTACKER, form(app + "/email", [("email", "x@lab.example")]))
        a = self.state(page)
        self.assertEqual(sent[0]["origin"], att)
        self.assertFalse(sent[0]["cookie_attached"])
        self.assertEqual(a, b)
        results["cross-site-post"] = (b, a, sent[0])

        # same-site sibling POST: different origin, same site -> Lax cookie sent, changed
        b = self.state(page)
        sent = self.submit_from(page, SIBLING, form(app + "/email", [("email", "s@lab.example")]))
        a = self.state(page)
        self.assertEqual(sent[0]["origin"], sib)  # cross-origin: Origin is the sibling
        self.assertTrue(sent[0]["cookie_attached"])
        self.assertEqual(a["email"], "s@lab.example")
        results["sibling-post"] = (b, a, sent[0])

        # cross-site top-level GET navigation to a state-changing GET: Lax cookie sent
        b = self.state(page)
        sent = self.navigate_from(page, ATTACKER, app + "/delete-item")
        a = self.state(page)
        self.assertTrue(sent[0]["cookie_attached"])
        self.assertEqual(a["deleted"], b["deleted"] + 1)
        results["cross-site-get"] = (b, a, sent[0])

        # token-checked twin from the sibling: cookie sent, 200 envelope, unchanged
        b = self.state(page)
        sent = self.submit_from(page, SIBLING, form(app + "/email-token", [("email", "t@lab.example")]))
        a = self.state(page)
        self.assertTrue(sent[0]["cookie_attached"])
        self.assertEqual(a, b)
        results["token-omit"] = (b, a, sent[0])

        # text/plain form carrying JSON: the lenient parser accepts it, the strict one refuses
        tp = form(app + "/api/profile", [('{"profile":"via-text-plain","x":"', '"}')], "text/plain")
        b = self.state(page)
        sent = self.submit_from(page, SIBLING, tp)
        a = self.state(page)
        self.assertEqual(sent[0]["content_type"], "text/plain")
        self.assertEqual(a["profile"], "via-text-plain")
        results["text-plain-lenient"] = (b, a, sent[0])
        strict = form(app + "/api/profile-strict", [('{"profile":"strict","x":"', '"}')], "text/plain")
        b = self.state(page)
        sent = self.submit_from(page, SIBLING, strict)
        a = self.state(page)
        self.assertEqual(a, b)
        results["text-plain-strict"] = (b, a, sent[0])

        # constant custom header: preflight refused, the POST never leaves the browser
        b = self.state(page)
        outcome, sent = self.script_from(page, SIBLING, (
            f"fetch('{app}/api/admin', {{method: 'POST', credentials: 'include', "
            "headers: {'X-CSRF': '1'}}).then(r => 'read:' + r.status).catch(e => 'error')"))
        a = self.state(page)
        self.assertEqual(outcome, "error")
        self.assertEqual([e["method"] for e in sent], ["OPTIONS"])
        self.assertEqual(a["admin"], b["admin"])
        results["custom-header"] = (b, a, sent[0])

        # simple credentialed fetch: response unreadable under CORS, write delivered anyway
        b = self.state(page)
        outcome, sent = self.script_from(page, SIBLING, (
            f"fetch('{app}/api/profile', {{method: 'POST', credentials: 'include', "
            "headers: {'Content-Type': 'text/plain'}, body: '{\"profile\":\"via-fetch\"}'})"
            ".then(r => 'read:' + r.status).catch(e => 'error')"))
        a = self.state(page)
        self.assertEqual(outcome, "error")             # the page cannot read the response
        self.assertEqual([e["method"] for e in sent], ["POST"])  # simple request: no preflight
        self.assertTrue(sent[0]["cookie_attached"])
        self.assertEqual(a["profile"], "via-fetch")    # ...yet the state changed
        results["simple-fetch"] = (b, a, sent[0])

        # --- SameSite=Strict victim: same-site siblings still carry it, cross-site GET does not
        strict_page = self.victim("strict")
        b = self.state(strict_page)
        sent = self.submit_from(strict_page, SIBLING, form(app + "/email", [("email", "ss@lab.example")]))
        a = self.state(strict_page)
        self.assertTrue(sent[0]["cookie_attached"])
        self.assertEqual(a["email"], "ss@lab.example")
        b2 = self.state(strict_page)
        sent2 = self.navigate_from(strict_page, ATTACKER, app + "/delete-item")
        a2 = self.state(strict_page)
        self.assertFalse(sent2[0]["cookie_attached"])
        self.assertEqual(a2["deleted"], b2["deleted"])

        # --- SameSite omitted: record whatever this build does on a fresh cookie
        omit_page = self.victim("omit")
        b = self.state(omit_page)
        sent = self.submit_from(omit_page, ATTACKER, form(app + "/email", [("email", "o@lab.example")]))
        a = self.state(omit_page)
        results["omitted-fresh"] = (b, a, sent[0])

        self.record_in_ledger(results)

    # ---------------- ledger
    def record_in_ledger(self, results):
        app = self.lab.origin(APP)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "camp"
            camp = write_campaign(root, "active", [], in_scope=[APP])
            ctx = Recon(camp, log=lambda _: None)
            self.addCleanup(ctx.store.close)
            # the Set-Cookie the lab really sent to the Lax victim (value dropped by request_meta)
            set_cookie = [("Set-Cookie", next(c for m, c in self.lab.set_cookies if m == "lax"))]
            ids = {}
            for path, method, body, ct in (("/email", "POST", ["email"], "application/x-www-form-urlencoded"),
                                           ("/delete-item", "GET", [], ""),
                                           ("/email-token", "POST", ["email", "csrf"],
                                            "application/x-www-form-urlencoded"),
                                           ("/api/profile", "POST", ["profile"], "application/json"),
                                           ("/api/profile-strict", "POST", ["profile"], "application/json"),
                                           ("/api/admin", "POST", [], "application/json")):
                aid = ctx.add_endpoint(app + path, "har", method=method, params=body)
                headers = [h for h in results["baseline"][2]["headers"] if h[0].lower() == "cookie"]
                if path == "/api/admin":
                    headers.append(("X-CSRF", "1"))
                meta = request_meta(headers, ct, [], body, set_cookie if path == "/email" else [])
                ctx.store.add_observation(aid, method, "victim", {"query": [], "body": body, "ids": {},
                                                                   "auth": True}, 200, "har",
                                          capture_key=f"lab:{path}", context={"csrf_meta": meta})
                ids[path] = aid
            led = CsrfLedger(ctx)
            led.sync()
            plan = led.plan(limit=50)
            context = {a["route"]: a["contexts"][0]["context_id"] for a in plan["actions"]}
            self.assertEqual(set(context), {"/email", "/delete-item", "/email-token", "/api/profile",
                                            "/api/profile-strict", "/api/admin"})
            evidence = root / "evidence"
            evidence.mkdir()

            def bundle(name, before, after, request):
                paths = {}
                for role, data in (("before", before), ("after", after), ("request", request)):
                    p = evidence / f"{name}-{role}.json"
                    p.write_text(json.dumps(data, sort_keys=True))
                    paths[role] = f"evidence/{p.name}"
                return [f"{r}={p}" for r, p in paths.items()]

            def base(route):
                b, a, req = results["baseline"]
                led.record(context[route], "baseline", "observed", browser=self.build,
                           artifacts=bundle(f"base{route.replace('/', '-')}", b, a, req))

            for route in context:
                base(route)
            att, sib = self.lab.origin(ATTACKER), self.lab.origin(SIBLING)

            # cross-site POST under Lax: a 200 envelope with an unchanged readback cannot
            # be recorded as observed; it is the negative it is
            b, a, req = results["cross-site-post"]
            arts = bundle("xs-post", b, a, req)
            with self.assertRaisesRegex(ValueError, "state change"):
                led.record(context["/email"], "cookie-delivery", "observed", variant="top-level-post",
                           initiator="cross-site", initiator_origin=att, delivery="form-post",
                           browser=self.build, artifacts=arts)
            led.record(context["/email"], "cookie-delivery", "negative", variant="top-level-post",
                       initiator="cross-site", initiator_origin=att, delivery="form-post",
                       browser=self.build, artifacts=arts,
                       note="Lax cookie withheld on cross-site POST; 200 error envelope; readback unchanged")

            b, a, req = results["sibling-post"]
            sibling = led.record(context["/email"], "cookie-delivery", "observed",
                                 variant="same-site-sibling", initiator="same-site",
                                 initiator_origin=sib, delivery="form-post", browser=self.build,
                                 prerequisite="owned lab sibling host",
                                 artifacts=bundle("sib-post", b, a, req))
            self.assertEqual(sibling["relationship"], "same-site")

            b, a, req = results["cross-site-get"]
            got = led.record(context["/delete-item"], "cookie-delivery", "observed",
                             variant="top-level-get", initiator="cross-site", initiator_origin=att,
                             delivery="navigation", browser=self.build,
                             artifacts=bundle("xs-get", b, a, req))
            self.assertEqual(got["relationship"], "cross-site")

            b, a, req = results["token-omit"]
            led.record(context["/email-token"], "token-enforcement", "negative",
                       variant="omit-all-channels", initiator="same-site", initiator_origin=sib,
                       delivery="form-post", browser=self.build, artifacts=bundle("tok", b, a, req),
                       note="cookie attached, token absent: 200 envelope, readback unchanged")

            b, a, req = results["text-plain-lenient"]
            led.record(context["/api/profile"], "representation", "observed", variant="text-plain",
                       initiator="same-site", initiator_origin=sib, delivery="form-post",
                       preflight="none", browser=self.build, prerequisite="owned lab sibling host",
                       artifacts=bundle("tp", b, a, req))
            b, a, req = results["text-plain-strict"]
            led.record(context["/api/profile-strict"], "representation", "negative",
                       variant="text-plain", initiator="same-site", initiator_origin=sib,
                       delivery="form-post", browser=self.build,
                       artifacts=bundle("tps", b, a, req), note="415 for text/plain; unchanged")

            b, a, req = results["custom-header"]
            arts = bundle("hdr", b, a, req)
            claim = dict(variant="required-header", initiator="same-site", initiator_origin=sib,
                         delivery="fetch", preflight="denied", browser=self.build,
                         prerequisite="owned lab sibling host")
            with self.assertRaisesRegex(ValueError, "state change"):  # the real, unchanged readback
                led.record(context["/api/admin"], "bff-protection", "observed", artifacts=arts, **claim)
            # even a bundle claiming a change contradicts a denied preflight
            contradictory = bundle("hdr-claim", b, dict(a, admin=a["admin"] + 1), req)
            with self.assertRaisesRegex(ValueError, "preflight"):
                led.record(context["/api/admin"], "bff-protection", "observed",
                           artifacts=contradictory, **claim)
            led.record(context["/api/admin"], "bff-protection", "negative", variant="required-header",
                       initiator="same-site", initiator_origin=sib, delivery="fetch",
                       preflight="denied", browser=self.build, artifacts=arts,
                       note="constant header forced a preflight; refused; POST never sent")

            b, a, req = results["simple-fetch"]
            led.record(context["/api/profile"], "cookie-delivery", "observed",
                       variant="credentialed-fetch", initiator="same-site", initiator_origin=sib,
                       delivery="fetch", preflight="none", browser=self.build,
                       prerequisite="owned lab sibling host", artifacts=bundle("sf", b, a, req),
                       note="response unreadable under CORS, write delivered")

            b, a, req = results["omitted-fresh"]
            changed = a != b
            led.record(context["/email"], "cookie-delivery", "observed" if changed else "negative",
                       variant="default-lax-age", initiator="cross-site", initiator_origin=att,
                       delivery="form-post", browser=self.build,
                       artifacts=bundle("omit", b, a, req),
                       note=f"fresh cookie without SameSite; attached={req['cookie_attached']}")
            self.assertEqual(changed, req["cookie_attached"])

            def card(route, case):
                for action in led.plan(limit=50)["actions"]:
                    if action["route"] == route:
                        return next(c for c in action["contexts"][0]["cases"] if c["case"] == case)

            def variant(route, case, vid):
                return next(v for v in card(route, case)["variants"] if v["id"] == vid)["state"]

            self.assertEqual(card("/email", "cookie-delivery")["outcome"], "observed")
            self.assertEqual(variant("/email", "cookie-delivery", "top-level-post"), "negative")
            self.assertEqual(card("/delete-item", "cookie-delivery")["outcome"], "observed")
            self.assertEqual(variant("/email-token", "token-enforcement", "omit-all-channels"),
                             "negative")
            self.assertEqual(card("/api/profile", "representation")["outcome"], "observed")
            self.assertEqual(variant("/api/profile-strict", "representation", "text-plain"), "negative")
            self.assertEqual(variant("/api/admin", "bff-protection", "required-header"), "negative")
            self.assertEqual(card("/email", "effect-handoff")["readiness"], "ready")
            self.assertEqual(card("/email-token", "effect-handoff")["readiness"], "waiting-effect")
            status = led.status()
            self.assertEqual(status["hosts"][0]["origin"], app)
            self.assertEqual(led.verify_artifacts()["missing_or_modified"], [])


if __name__ == "__main__":
    unittest.main()
