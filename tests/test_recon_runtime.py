"""Runtime (headless browser) harvest against a lab SPA. Skipped without playwright:
    .venv/bin/python -m unittest tests.test_recon_runtime
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import playwright  # noqa: F401
    HAVE_PLAYWRIGHT = True
except ImportError:
    HAVE_PLAYWRIGHT = False

from recon.pipeline import Recon
from tests.test_recon import LabServer, write_campaign

SPA_HTML = """<html><head><title>SPA</title></head><body><div id="app"></div>
<img src="https://tracker.thirdparty.example/p.gif">
<script src="/app.js"></script></body></html>"""
SPA_JS = r"""
const router = {mode:"hash", routes:[{path:"/admin"}, {path:"/billing"}]};
async function boot() {
  const me = await fetch("/api/auth/me").then(r => r.json()).catch(() => ({}));
  if (!(me.data && me.data.user)) { location.hash = "#/login"; }
  render();
}
function render() {
  const r = location.hash.slice(1) || "/";
  const app = document.getElementById("app");
  if (r === "/login") { app.innerHTML = "<h1>login</h1>"; return; }
  if (r.startsWith("/admin")) { fetch("/api/admin/users?page=1"); }
  if (r.startsWith("/billing")) {
    fetch("/api/billing/invoices", {method: "POST", headers: {"content-type": "application/json"},
          body: JSON.stringify({invoice_id: 7, coupon: "x"})});
  }
  app.innerHTML = '<div role="tab" id="t1">Exports</div>' +
                  '<aside><a href="/danger/delete?id=1">delete everything</a></aside>';
  document.getElementById("t1").onclick = () =>
    fetch("/api/reports/export", {method: "POST", body: JSON.stringify({format: "pdf", url: "x"})});
  try { new WebSocket("ws://" + location.host + "/ws"); } catch (e) {}
}
window.addEventListener("hashchange", render);
boot();
"""


@unittest.skipUnless(HAVE_PLAYWRIGHT, "playwright not installed")
class RuntimeHarvestTests(unittest.TestCase):
    def test_mocked_login_spa(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "site").mkdir()
            (root / "site" / "index.html").write_text(SPA_HTML)
            (root / "site" / "app.js").write_text(SPA_JS)
            with LabServer(root / "site") as lab:
                base = f"http://127.0.0.1:{lab.port}"
                camp = write_campaign(root / "camp", "active", [base + "/"], runtime={"enabled": True})
                ctx = Recon(camp, log=lambda m: None)
                stats = ctx.run()
                hits = list(lab.hits)
            runtime_job = [j for j in ctx.store.jobs() if j["kind"] == "runtime"][0]
            self.assertEqual(runtime_job["state"], "done", runtime_job["note"])
            self.assertEqual(stats["failed"], 0)
            eps = {e["value"][len(base):]: e["attrs"] for e in ctx.store.assets("endpoint")}
            for path in ("/api/auth/me", "/api/admin/users", "/api/billing/invoices",
                         "/api/reports/export"):
                self.assertIn("runtime", eps[path]["sources"], path)
            self.assertEqual(eps["/api/billing/invoices"]["methods"], ["POST"])
            self.assertIn("invoice_id", eps["/api/billing/invoices"]["params"])
            self.assertIn("url", eps["/api/reports/export"]["params"])  # reached via tab click
            self.assertIn("/danger/delete", eps)  # recorded, not visited
            # the backend never saw an API call, the delete link, or the websocket
            self.assertFalse([h for h in hits if h.startswith(("/api", "/danger", "/ws"))], hits)
            self.assertIn("https://tracker.thirdparty.example",
                          {a["value"] for a in ctx.store.assets("intel")})
            svc = ctx.store.find_asset("service", base)["attrs"]
            self.assertEqual(svc["runtime"]["login_gated"], 0)
            self.assertGreaterEqual(svc["runtime"]["pages"], 3)


if __name__ == "__main__":
    unittest.main()
