"""Finding stages/links/chains, exploit lookup (searchsploit/Sploitus/KEV) and agent briefs.

Owned loopback lab + fake searchsploit + KEV fixture; no third-party network access.
"""
import http.server
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.brief import render, write_briefs
from recon.campaign import PolicyViolation
from recon.cli import main as cli_main
from recon.findings import Findings, StageError, write_findings
from recon.pipeline import Recon
from recon.vulnintel import extract_versions, lookup, title_covers
from recon.net import FetchError
from tests.test_recon import write_campaign

HTML = ('<html><head><meta name="generator" content="WordPress 5.8.1" />'
        '<script src="/jq.js"></script></head><body>hi</body></html>')
JQ = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */ var x=1;"
KEV = {"vulnerabilities": [
    {"cveID": "CVE-2021-41773", "vendorProject": "Apache", "product": "HTTP Server",
     "vulnerabilityName": "Apache HTTP Server Path Traversal", "dateAdded": "2021-11-03",
     "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2020-11023", "vendorProject": "JQuery", "product": "JQuery",
     "vulnerabilityName": "jQuery XSS", "dateAdded": "2025-01-23",
     "knownRansomwareCampaignUse": "Unknown"},
]}
FAKE_SEARCHSPLOIT = r'''#!/usr/bin/env python3
import json, sys
q = sys.argv[-1].lower()
db = [
  {"Title": "Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)",
   "EDB-ID": "50383", "Type": "webapps", "Date_Published": "2021-10-06", "Codes": "CVE-2021-41773"},
  {"Title": "Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) (2)",
   "EDB-ID": "50512", "Type": "webapps", "Date_Published": "2021-11-11", "Codes": "CVE-2021-42013"},
  {"Title": "WordPress Plugin Foo 5.8.1 - SQL Injection", "EDB-ID": "1", "Type": "webapps",
   "Date_Published": "2021-01-01", "Codes": ""},
  {"Title": "jQuery < 3.5.0 - Cross-Site Scripting", "EDB-ID": "49766", "Type": "webapps",
   "Date_Published": "2021-04-01", "Codes": "CVE-2020-11023"},
]
words = q.split()  # like searchsploit: every term must appear in the title
print(json.dumps({"SEARCH": q, "RESULTS_EXPLOIT": [e for e in db
      if all(w in e["Title"].lower() for w in words)], "RESULTS_SHELLCODE": []}))
'''


class VersionLab:
    def __init__(self):
        self.hits = []
        lab = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                lab.hits.append(self.path)
                body, ctype, code = b"not found", "text/plain", 404
                if self.path == "/":
                    body, ctype, code = HTML.encode(), "text/html", 200
                elif self.path == "/jq.js":
                    body, ctype, code = JQ.encode(), "application/javascript", 200
                self.send_response(code)
                self.send_header("Server", "Apache/2.4.49 (Unix)")
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def version_string(self):
                return "Apache/2.4.49 (Unix)"

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


class ParserTests(unittest.TestCase):
    def test_title_covers(self):
        self.assertEqual(title_covers("Apache Tomcat < 9.0.31 - Ghostcat", "9.0.30"), "range")
        self.assertIsNone(title_covers("Apache Tomcat < 9.0.31 - Ghostcat", "9.0.31"))
        self.assertEqual(title_covers("Apache HTTP Server 2.4.49 - Path Traversal", "2.4.49"), "exact")
        self.assertIsNone(title_covers("Apache HTTP Server 2.4.50 - RCE (2)", "2.4.49"))
        self.assertEqual(title_covers("Foo 2.0.0 < 2.3.1 - RCE", "2.1.4"), "range")
        self.assertIsNone(title_covers("Foo 2.0.0 < 2.3.1 - RCE", "1.9"))
        self.assertIsNone(title_covers("jQuery 1.2 - XSS", "1.12.4"))

    def test_extract_versions(self):
        got = {(p, v) for p, v, _ in extract_versions(
            {"server": "Apache/2.4.49 (Unix) OpenSSL/1.1.1k", "x-powered-by": "PHP/7.4.3",
             "x-jenkins": "2.401.1"},
            '<meta name="generator" content="Drupal 9 (https://www.drupal.org)">')}
        self.assertEqual(got, {("apache-httpd", "2.4.49"), ("openssl", "1.1.1k"),
                               ("php", "7.4.3"), ("jenkins", "2.401.1"), ("drupal", "9")})


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.camp = write_campaign(self.root / "camp", "passive", [], in_scope=["acme.test"])
        self.ctx = Recon(self.camp, log=lambda m: None)
        self.fx = Findings(self.ctx)
        self.url = "https://acme.test/api/orders/1"
        self.asset, _ = self.ctx.store.upsert_asset("endpoint", self.url, "acme.test")

    def tearDown(self):
        self.ctx.store.close()
        self.tmp.cleanup()

    def art(self, name, text):
        p = self.root / name
        p.write_text(text)
        return p

    def test_gates(self):
        fid, created = self.fx.add("IDOR on orders", "idor-bola", asset_id=self.asset)
        self.assertTrue(created)
        cov = {(c["asset_id"], c["bug_class"]): c["status"] for c in self.ctx.store.coverage()}
        self.assertEqual(cov[(self.asset, "idor-bola")], "queued")
        with self.assertRaises(StageError):
            self.fx.move(fid, "reported")  # can't skip confirmation
        with self.assertRaises(StageError):
            self.fx.move(fid, "confirmed", replay=self.art("r.txt", "200 bob's order"))
        same = self.art("same.txt", "200 bob's order")
        with self.assertRaises(StageError):
            self.fx.move(fid, "confirmed", replay=same, control=same)
        with self.assertRaises(StageError):
            self.fx.move(fid, "killed")  # reason required
        f = self.fx.move(fid, "confirmed", replay=self.art("r.txt", "200 bob's order"),
                         control=self.art("c.txt", "403 forbidden (alice own session)"))
        self.assertEqual(f["stage"], "confirmed")
        ev = self.fx.events(fid)[-1]["evidence"]
        self.assertTrue((self.camp.root / ev["control"]["stored"]).exists())
        cov = {(c["asset_id"], c["bug_class"]): c["status"] for c in self.ctx.store.coverage()}
        self.assertEqual(cov[(self.asset, "idor-bola")], "confirmed")
        with self.assertRaises(StageError):
            self.fx.move(fid, "impact-proven")  # needs --impact
        self.fx.move(fid, "impact-proven", impact=self.art("i.txt", "PII of 3 users"),
                     severity="high")
        self.fx.move(fid, "reported")
        self.fx.move(fid, "duplicate", note="dup of #123456")
        with self.assertRaises(StageError):
            self.fx.move(fid, "accepted")  # terminal
        self.assertEqual([e["to_stage"] for e in self.fx.events(fid)],
                         ["lead", "confirmed", "impact-proven", "reported", "duplicate"])
        self.assertEqual(self.fx.outcome_table(),
                         [{"bug_class": "idor-bola", "tech": "(unknown)", "outcome": "duplicate", "n": 1}])

    def test_out_of_scope_refused(self):
        with self.assertRaises(StageError):
            self.fx.add("x", "xss", url="https://evil.example/")

    def test_chains_and_hints(self):
        a, _ = self.fx.add("open redirect", "open-redirect", url="https://acme.test/r")
        b, _ = self.fx.add("oauth authorize", "oauth", url="https://acme.test/oauth/authorize")
        c, _ = self.fx.add("token -> admin", "access-control", url="https://acme.test/admin")
        hints = self.fx.chain_hints()
        self.assertTrue(any(h["a"]["id"] == a and h["b"]["id"] == b for h in hints))
        self.fx.link(a, "yields-token", b)
        self.assertFalse(self.fx.link(a, "yields-token", b))  # idempotent
        self.fx.link(b, "escalates-via", c)
        chains = self.fx.chains()
        self.assertEqual([[s["finding"]["id"] for s in ch] for ch in chains], [[a, b, c]])
        self.assertFalse(any(h["a"]["id"] == a and h["b"]["id"] == b for h in self.fx.chain_hints()))
        self.fx.move(b, "killed", note="redirect_uri strictly matched")
        self.assertEqual(self.fx.chains(), [])
        with self.assertRaises(StageError):
            self.fx.link(a, "made-up", c)
        text = write_findings(self.ctx).read_text()
        self.assertIn("## Chain hints", text)

    def test_cli(self):
        rc = cli_main(["finding", "add", str(self.camp.root), "--title", "SSRF in export",
                       "--class", "ssrf", "--url", "https://acme.test/export", "--severity", "high"])
        self.assertEqual(rc, 0)
        rc = cli_main(["finding", "move", str(self.camp.root), "1", "confirmed"])
        self.assertEqual(rc, 1)  # refused without artifacts
        self.assertIn("SSRF in export", (self.camp.root / "findings.md").read_text())


class LookupTests(unittest.TestCase):
    def test_lab_lookup(self):
        with tempfile.TemporaryDirectory() as d, VersionLab() as lab:
            root = Path(d)
            ss = root / "bin" / "searchsploit"
            ss.parent.mkdir()
            ss.write_text(FAKE_SEARCHSPLOIT)
            ss.chmod(ss.stat().st_mode | stat.S_IEXEC)
            kev = root / "kev.json"
            kev.write_text(json.dumps(KEV))
            base = f"http://127.0.0.1:{lab.port}"
            camp = write_campaign(root / "camp", "active", [base + "/"])
            ctx = Recon(camp, log=lambda m: None)
            ctx.run()
            hits_before = list(lab.hits)
            sent = []

            def fake_post(url, payload, purpose, **k):
                sent.append(payload)
                raise FetchError("offline fixture provider unavailable")
            ctx.passive.post_json = fake_post
            stats = lookup(ctx, kev_file=kev, searchsploit_bin=str(ss), log=lambda m: None)
            self.assertEqual(lab.hits, hits_before)  # lookup never touches the target
            self.assertTrue(sent)
            self.assertFalse([p for p in sent if "127.0.0.1" in json.dumps(p)])
            leads = Findings(ctx).all("lead")
            by_prod = {f["tech"][0]: f for f in leads}
            self.assertIn("apache-httpd", by_prod)
            apache = by_prod["apache-httpd"]
            self.assertEqual(apache["bug_class"], "known-cve")
            self.assertIn("CVE-2021-41773", " ".join(apache["detail"]["why"]))
            edb = {e["id"] for e in apache["detail"]["exploits"]}
            self.assertIn("EDB-50383", edb)
            self.assertNotIn("EDB-50512", edb)  # 2.4.50-only exploit filtered out
            self.assertIn("jquery", by_prod)
            # range title "jQuery < 3.5.0" found via the product-only query
            self.assertIn("EDB-49766", {e["id"] for e in by_prod["jquery"]["detail"]["exploits"]})
            hints = Findings(ctx).chain_hints()
            self.assertFalse([h for h in hints if "jquery" in h["a"]["tech"] + h["b"]["tech"]])
            self.assertGreater(apache["priority"], by_prod["jquery"]["priority"])
            self.assertEqual(leads[0]["id"], apache["id"])  # highest priority first
            # the only WordPress hit is a plugin advisory: says nothing about core 5.8.1
            self.assertNotIn("wordpress", by_prod)
            self.assertTrue(apache["detail"]["preconditions"][0].startswith("Version evidence"))
            again = lookup(ctx, kev_file=kev, searchsploit_bin=str(ss), log=lambda m: None)
            self.assertEqual(again["leads_new"], 0)
            self.assertEqual(again["leads_updated"], stats["leads_new"])
            ctx.store.close()

    def test_post_json_refusals(self):
        with tempfile.TemporaryDirectory() as d:
            camp = write_campaign(Path(d) / "camp", "passive", [], in_scope=["acme.test"])
            ctx = Recon(camp, log=lambda m: None)
            with self.assertRaises(PolicyViolation):
                ctx.passive.post_json("https://acme.test/search", {"query": "x"}, "t")
            with self.assertRaises(PolicyViolation):
                ctx.passive.post_json("https://sploitus.com/search",
                                      {"query": "nginx on api.acme.test"}, "t")
            self.assertEqual(ctx.store.request_count(), 0)
            ctx.store.close()


class BriefTests(unittest.TestCase):
    def test_pre_authorized_brief(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "camp"
            camp = write_campaign(root, "active", [], in_scope=["*.acme.test", "acme.test"],
                                  out=["/logout", "status.acme.test"])
            raw = json.loads((root / "scope.json").read_text())
            raw["rules"] = ["No automated scanners above 5 rps"]
            raw["excluded_bug_classes"] = ["clickjacking"]
            (root / "scope.json").write_text(json.dumps(raw))
            from recon.campaign import Campaign
            camp = Campaign.load(root)
            text = render(camp, "hunter")
            for needle in ("pre-authorized", "Do not ask for permission", "`*.acme.test`",
                           "`status.acme.test`", "No automated scanners above 5 rps",
                           "`clickjacking`", "OutOfScope", f"finding add {camp.name}"):
                self.assertIn(needle, text)
            self.assertNotIn("{{", text)
            paths = write_briefs(camp)
            self.assertEqual(sorted(p.name for p in paths),
                             ["hunter.md", "reporter.md", "validator.md"])
            self.assertIn("--control", (root / "agents" / "validator.md").read_text())


if __name__ == "__main__":
    unittest.main()
