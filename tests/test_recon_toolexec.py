"""`recon exec`: scope, methods, pacing, budget and flag refusals for external tools.

Offline except for one owned-loopback run against `EchoServer` (127.0.0.1), driven by a
fake tool binary written into the test's own temporary directory. No real scanner is
installed or invoked, and no traffic leaves the loopback interface.

The contract under test (plans/artex-adoption.md §3.1, decision D1/D2):
  * an unknown tool, an out-of-scope target or a refused flag stops the run before
    anything is launched;
  * a tool runs only in a policy mode and with method grants that cover what it sends;
  * the declared estimate is pre-charged to the same campaign counter `recon send`
    uses, and is never refunded;
  * rate, output and cap flags come from policy and cannot be overridden from argv.
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.campaign import Campaign, OutOfScope, PolicyViolation
from recon.cli import main
from recon.pipeline import Recon
from recon.toolexec import (ALWAYS_AVAILABLE, PROFILES, Profile, Refused, execute,
                            prepare)
from tests.test_recon_write import EchoServer


def _campaign(root: Path, *, mode="active", methods=("GET", "HEAD"),
              max_rps=5, budget=10_000, hosts=("127.0.0.1", "app.example.test")) -> Recon:
    root.mkdir(parents=True, exist_ok=True)
    (root / "scope.json").write_text(json.dumps({
        "program": "lab", "seeds": [], "in_scope": list(hosts),
        "out_of_scope": ["/logout"],
        "policy": {"mode": mode, "max_rps": max_rps, "allowed_methods": list(methods),
                   "max_requests": 1000, "max_campaign_requests": budget,
                   "user_agent": "bugvault-test"}}))
    return Recon(Campaign.load(root), log=lambda _: None)


def _fake_tool(directory: Path, name: str, body: str) -> Path:
    """A stand-in binary. Tests inject it through `prepare(resolve=...)`."""
    path = directory / name
    path.write_text("#!/usr/bin/env python3\n" + body)
    path.chmod(0o700)
    return path


class ExecRefusalTests(unittest.TestCase):
    """Everything that must stop before a process is launched."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.ctx = _campaign(self.root)
        self.addCleanup(self.ctx.store.close)
        self.resolve = lambda binary: "/usr/bin/true"

    def prep(self, tool, argv, estimate=10, **kw):
        kw.setdefault("resolve", self.resolve)
        return prepare(self.ctx, tool, argv, estimate, **kw)

    def test_the_tool_allowlist_is_closed(self):
        self.assertEqual(sorted(PROFILES),
                         ["dalfox", "ffuf", "httpx", "katana", "nuclei", "sqlmap"])
        with self.assertRaisesRegex(Refused, "unknown tool"):
            self.prep("wget", ["-u", "https://app.example.test/"])

    def test_an_out_of_scope_target_refuses_the_whole_run(self):
        with self.assertRaises(OutOfScope):
            self.prep("httpx", ["-u", "https://evil.test/"])
        # One bad target among good ones still refuses everything.
        with self.assertRaises(OutOfScope):
            self.prep("httpx", ["-u", "https://app.example.test/", "-u", "https://evil.test/"])

    def test_a_target_behind_an_unknown_flag_is_still_scope_checked(self):
        """Fail closed: a flag alias the profile does not know is not an escape hatch."""
        with self.assertRaises(OutOfScope):
            self.prep("httpx", ["--some-future-alias", "https://evil.test/"])

    def test_a_non_http_scheme_is_refused(self):
        with self.assertRaises(OutOfScope):
            self.prep("httpx", ["-u", "file:///etc/passwd"])

    def test_a_run_with_no_visible_target_is_refused(self):
        with self.assertRaisesRegex(Refused, "no target found"):
            self.prep("httpx", ["-silent-ish"])

    def test_passive_mode_runs_no_tool(self):
        ctx = _campaign(Path(self.tmp.name) / "passive", mode="passive")
        self.addCleanup(ctx.store.close)
        with self.assertRaisesRegex(PolicyViolation, "needs mode 'active'"):
            prepare(ctx, "httpx", ["-u", "https://app.example.test/"], 10, resolve=self.resolve)

    def test_post_is_always_available_to_an_allowlisted_tool(self):
        """Operator decision 2026-11-22: a POST grant no longer gates a scanner."""
        self.assertEqual(ALWAYS_AVAILABLE, frozenset({"GET", "HEAD", "POST"}))
        # The campaign grants GET/HEAD only, and nuclei still runs.
        plan = self.prep("nuclei", ["-u", "https://app.example.test/"])
        self.assertEqual(plan["methods"], ["GET", "POST"])
        for tool, argv in (("dalfox", ["url", "https://app.example.test/"]),
                           ("sqlmap", ["-u", "https://app.example.test/?q=1"])):
            self.assertEqual(self.prep(tool, argv)["tool"], tool)

    def test_verb_level_mutation_still_needs_an_explicit_grant(self):
        """PUT/PATCH/DELETE are not in ALWAYS_AVAILABLE, so the gate still bites."""
        PROFILES["fixture-put"] = Profile("fixture-put", "true", "active", ("GET", "PUT"),
                                          target_flags=("-u",))
        self.addCleanup(PROFILES.pop, "fixture-put", None)
        with self.assertRaisesRegex(Refused, "does not grant PUT"):
            self.prep("fixture-put", ["-u", "https://app.example.test/"])
        ctx = _campaign(Path(self.tmp.name) / "put", methods=("GET", "PUT"))
        self.addCleanup(ctx.store.close)
        self.assertEqual(prepare(ctx, "fixture-put", ["-u", "https://app.example.test/"],
                                 10, resolve=self.resolve)["tool"], "fixture-put")

    def test_ffuf_needs_a_loud_campaign(self):
        """Path guessing is `loud` in scope-policy, not merely `active`."""
        with self.assertRaisesRegex(PolicyViolation, "needs mode 'loud'"):
            self.prep("ffuf", ["-u", "https://app.example.test/FUZZ"])
        ctx = _campaign(Path(self.tmp.name) / "loud", mode="loud")
        self.addCleanup(ctx.store.close)
        plan = prepare(ctx, "ffuf", ["-u", "https://app.example.test/FUZZ"], 10,
                       resolve=self.resolve)
        # FUZZ is replaced only for the scope check; the tool still gets it verbatim.
        self.assertEqual(plan["targets"][0]["checked_as"], "https://app.example.test/fuzz")
        self.assertIn("-u", plan["caller_argv"])
        self.assertIn("https://app.example.test/FUZZ", plan["caller_argv"])

    def test_dangerous_flags_are_refused_per_tool(self):
        target = ["-u", "https://app.example.test/?q=1"]
        for flag in ("--os-shell", "--tamper", "--file-write", "--crawl", "-g"):
            with self.assertRaisesRegex(Refused, "refused by its profile"):
                self.prep("sqlmap", [*target, flag])
        for flag in ("-interactsh-server", "-headless", "-update-templates", "-proxy"):
            with self.assertRaisesRegex(Refused, "refused by its profile"):
                self.prep("nuclei", [*target, flag])
        with self.assertRaisesRegex(Refused, "refused by its profile"):
            self.prep("dalfox", ["url", "https://app.example.test/", "--found-action"])

    def test_injected_flags_cannot_be_overridden_from_argv(self):
        for flag in ("-rate-limit", "-o", "-json"):
            with self.assertRaisesRegex(Refused, "set by recon"):
                self.prep("httpx", ["-u", "https://app.example.test/", flag, "99"])

    def test_host_and_proxy_headers_are_refused(self):
        with self.assertRaisesRegex(Refused, "header overrides are refused"):
            self.prep("httpx", ["-u", "https://app.example.test/", "-H", "Host: evil.test"])

    def test_dalfox_runs_only_as_url_or_file(self):
        for argv in (["pipe"], ["server"], []):
            with self.assertRaisesRegex(Refused, "url <target>"):
                self.prep("dalfox", argv)

    def test_a_target_list_must_live_inside_the_campaign(self):
        outside = Path(self.tmp.name) / "targets.txt"
        outside.write_text("https://app.example.test/\n")
        with self.assertRaisesRegex(Refused, "inside the campaign directory"):
            self.prep("httpx", ["-l", str(outside)])
        inside = self.root / "targets.txt"
        inside.write_text("https://app.example.test/a\nhttps://app.example.test/b\n# note\n")
        plan = self.prep("httpx", ["-l", "targets.txt"])
        self.assertEqual(len(plan["targets"]), 2)

    def test_every_target_in_a_list_is_scope_checked(self):
        inside = self.root / "mixed.txt"
        inside.write_text("https://app.example.test/a\nhttps://evil.test/b\n")
        with self.assertRaises(OutOfScope):
            self.prep("httpx", ["-l", "mixed.txt"])

    def test_a_blocked_host_is_refused(self):
        blocked = {"app.example.test": {"reason": "429", "request_id": 1}}
        with self.assertRaisesRegex(Refused, "deferred by"):
            self.prep("httpx", ["-u", "https://app.example.test/"], blocked=blocked)

    def test_a_missing_binary_is_an_environment_block_not_a_detour(self):
        with self.assertRaisesRegex(Refused, "recon operator ask") as caught:
            prepare(self.ctx, "httpx", ["-u", "https://app.example.test/"], 10,
                    resolve=lambda binary: None)
        self.assertIn("--reason environment", str(caught.exception))

    def test_the_estimate_is_bounded(self):
        for bad in (0, -1, 10_001, 2.5, True):
            with self.assertRaisesRegex(Refused, r"--estimate must be an integer"):
                self.prep("httpx", ["-u", "https://app.example.test/"], bad)

    def test_argv_hygiene(self):
        with self.assertRaisesRegex(Refused, "control characters"):
            self.prep("httpx", ["-u", "https://app.example.test/\n-u https://evil.test/"])
        with self.assertRaisesRegex(Refused, "at most"):
            self.prep("httpx", ["-u", "https://app.example.test/", "x" * 5000])
        with self.assertRaisesRegex(Refused, "longer than"):
            self.prep("httpx", ["-u", "https://app.example.test/"] + ["-x"] * 200)

    def test_pacing_and_caps_come_from_policy(self):
        plan = self.prep("httpx", ["-u", "https://app.example.test/"], 100)
        self.assertEqual(plan["rps"], 5)          # policy.max_rps
        self.assertEqual(plan["seconds"], 20)     # ceil(100 / 5)
        self.assertEqual(plan["timeout_seconds"], 140)

    def test_plan_launches_nothing(self):
        before = self.ctx.store.network_attempts()
        self.prep("httpx", ["-u", "https://app.example.test/"], 50)
        self.assertEqual(self.ctx.store.network_attempts(), before)
        self.assertFalse((self.root / ".recon" / "exec").exists())


class ExecBudgetTests(unittest.TestCase):
    """The estimate is charged to the same counter `recon send` uses, and never returned."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "campaign"
        self.ctx = _campaign(self.root, budget=120)
        self.addCleanup(self.ctx.store.close)
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()

    def _plan(self, estimate, tool="httpx", argv=None, records=0):
        body = ("import sys, pathlib\n"
                "out = sys.argv[sys.argv.index('-o') + 1]\n"
                f"pathlib.Path(out).write_text(''.join('{{\"url\": \"u\"}}\\n' "
                f"for _ in range({records})))\n")
        fake = _fake_tool(self.bin, tool, body)
        return prepare(self.ctx, tool, argv or ["-u", "https://app.example.test/"],
                       estimate, resolve=lambda b: str(fake))

    def test_the_estimate_is_charged_before_the_tool_starts(self):
        record = execute(self.ctx, self._plan(40), engagement="e1", import_output=False)
        self.assertEqual(record["charged"], 40)
        self.assertEqual(self.ctx.store.network_attempts(), 40)

    def test_an_unused_estimate_is_never_refunded(self):
        """Decision D2: the budget may only err towards stopping early."""
        record = execute(self.ctx, self._plan(40, records=1), engagement="e1",
                         import_output=False)
        self.assertEqual(record["result_records"], 1)
        self.assertEqual(record["charged"], 40)
        self.assertEqual(self.ctx.store.network_attempts(), 40)
        self.assertIn("stays charged", record["refund"])

    def test_result_records_beyond_the_estimate_are_charged_after_the_run(self):
        """N result records prove at least N requests, so reconciliation goes up."""
        record = execute(self.ctx, self._plan(5, records=9), engagement="e1",
                         import_output=False)
        self.assertEqual(record["charged"], 9)
        self.assertIn("+4", record["reconciled"])
        self.assertEqual(self.ctx.store.network_attempts(), 9)

    def test_a_run_that_does_not_fit_the_budget_is_refused(self):
        execute(self.ctx, self._plan(100), engagement="e1", import_output=False)
        with self.assertRaisesRegex(Refused, "cannot cover"):
            execute(self.ctx, self._plan(50), engagement="e1", import_output=False)
        # Nothing was charged by the refused run.
        self.assertEqual(self.ctx.store.network_attempts(), 100)

    def test_exec_and_send_share_one_counter(self):
        """D1: the two sending paths cannot exceed one campaign's budget together."""
        execute(self.ctx, self._plan(119), engagement="e1", import_output=False)
        self.assertTrue(self.ctx.store.reserve_network_attempt(120))   # the 120th
        self.assertFalse(self.ctx.store.reserve_network_attempt(120))  # `send` is now stopped

    def test_the_run_is_recorded_privately_with_hashes(self):
        record = execute(self.ctx, self._plan(10, records=2), engagement="e1",
                         import_output=False)
        run = self.root / ".recon" / "exec" / record["run_id"] / "run.json"
        self.assertTrue(run.is_file())
        self.assertEqual(stat.S_IMODE(run.stat().st_mode), 0o600)
        saved = json.loads(run.read_text())
        self.assertEqual(saved["estimate"], 10)
        self.assertTrue(all(len(art["sha256"]) == 64 for art in saved["artifacts"]))
        ledger = self.root / ".recon" / "engagements" / "e1" / "exec-runs.jsonl"
        self.assertEqual(len(ledger.read_text().strip().splitlines()), 1)
        self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o600)

    def test_the_injected_argv_is_what_ran(self):
        record = execute(self.ctx, self._plan(10), engagement="e1", import_output=False)
        self.assertIn("-rate-limit", record["argv"])
        self.assertEqual(record["argv"][record["argv"].index("-rate-limit") + 1], "5")
        self.assertIn("-json", record["argv"])

    def test_a_tool_that_times_out_is_killed_and_still_charged(self):
        fake = _fake_tool(self.bin, "httpx", "import time\ntime.sleep(30)\n")
        plan = prepare(self.ctx, "httpx", ["-u", "https://app.example.test/"], 1,
                       resolve=lambda b: str(fake))
        plan["timeout_seconds"] = 1
        record = execute(self.ctx, plan, engagement="e1", import_output=False)
        self.assertTrue(record["timed_out"])
        self.assertEqual(self.ctx.store.network_attempts(), 1)

    def test_pacing_is_held_for_the_whole_run_window(self):
        """A later `recon send` waits the scan out instead of stacking on it.

        Single-process only: `host_pacing` is not atomic across simultaneous processes
        (recon/README.md), so this is the best-effort clock, not a concurrent gate.
        """
        execute(self.ctx, self._plan(50), engagement="e1", import_output=False)
        wait = self.ctx.store.reserve_pacing_slot("app.example.test", 0.2)
        self.assertGreater(wait, 0.0)


class ExecLoopbackTests(unittest.TestCase):
    """One real tool process making real requests, to an owned loopback server."""

    def test_a_fake_tool_reaches_the_owned_server_and_imports_its_surfaces(self):
        with tempfile.TemporaryDirectory() as tmp, EchoServer() as lab:
            root = Path(tmp) / "campaign"
            ctx = _campaign(root, hosts=[f"127.0.0.1:{lab.port}"])
            self.addCleanup(ctx.store.close)
            target = f"http://127.0.0.1:{lab.port}/probe"
            body = ("import json, pathlib, sys, urllib.request\n"
                    "url = sys.argv[sys.argv.index('-u') + 1]\n"
                    "out = sys.argv[sys.argv.index('-o') + 1]\n"
                    "code = urllib.request.urlopen(url, timeout=5).status\n"
                    "pathlib.Path(out).write_text(json.dumps("
                    "{'url': url, 'status_code': code}) + '\\n')\n")
            fake = _fake_tool(Path(tmp), "httpx", body)
            plan = prepare(ctx, "httpx", ["-u", target], 5, resolve=lambda b: str(fake))
            record = execute(ctx, plan, engagement="lab")

            self.assertEqual(record["exit_code"], 0)
            self.assertEqual([seen["path"] for seen in lab.seen], ["/probe"])
            self.assertEqual(record["result_records"], 1)
            # The artifact went through the offline importer as a surface, not a finding.
            self.assertEqual(record["import"]["accepted"], 1)
            self.assertTrue(any(a["value"] == target
                                for a in ctx.store.assets("endpoint")))


class ExecCliTests(unittest.TestCase):
    def test_plan_mode_through_the_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "campaign"
            _campaign(root).store.close()
            self.assertEqual(main(["exec", str(root), "--tool", "httpx", "--engagement", "e1",
                                   "--estimate", "10", "--plan", "--",
                                   "-u", "https://app.example.test/"]), 0)
            # An out-of-scope target is a refusal, not a run.
            self.assertEqual(main(["exec", str(root), "--tool", "httpx", "--engagement", "e1",
                                   "--estimate", "10", "--plan", "--",
                                   "-u", "https://evil.test/"]), 1)

    def test_the_cli_rejects_an_unlisted_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "campaign"
            _campaign(root).store.close()
            with self.assertRaises(SystemExit):
                main(["exec", str(root), "--tool", "curl", "--engagement", "e1",
                      "--estimate", "10", "--", "-u", "https://app.example.test/"])


class NucleiImportTests(unittest.TestCase):
    """A nuclei match imports as an unverified surface claim, never as a finding."""

    def test_a_match_becomes_a_labelled_surface(self):
        from recon.ingest import FORMATS, import_artifact
        self.assertIn("nuclei", FORMATS)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "campaign"
            ctx = _campaign(root)
            self.addCleanup(ctx.store.close)
            artifact = root / "nuclei.jsonl"
            artifact.write_text(json.dumps({
                "template-id": "apache-detect", "info": {"severity": "HIGH"},
                "matched-at": "https://app.example.test/server-status"}) + "\n" + json.dumps({
                "template-id": "out-of-scope", "info": {"severity": "critical"},
                "matched-at": "https://evil.test/x"}) + "\n")
            stats = import_artifact(ctx, artifact, "nuclei")
            self.assertEqual(stats["accepted"], 2)
            self.assertEqual(stats["out_of_scope"], 1)
            self.assertTrue(any(a["value"].endswith("/server-status")
                                for a in ctx.store.assets("endpoint")))
            # Scanner claims land on the origin, exactly as httpx's do
            # (tests/test_recon_ingest.py::test_httpx_keeps_imported_claims_separate).
            attrs = ctx.store.assets("service")[0]["attrs"]
            self.assertEqual(attrs["unverified_scanner_claim"], "nuclei")
            self.assertEqual(attrs["reported_severity"], "high")
            self.assertEqual(attrs["reported_template"], "apache-detect")
            # A "critical" from a scanner confirms nothing: no coverage row is
            # promoted and no fact is asserted on the strength of its opinion.
            self.assertFalse([r for r in ctx.store.coverage() if r["status"] == "confirmed"])
            self.assertFalse(ctx.store.facts())


if __name__ == "__main__":
    unittest.main()
