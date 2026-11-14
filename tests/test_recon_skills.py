"""One skills folder (.claude/skills), well-formed skills, and the coverage -> skill trigger."""
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recon.brief import render
from recon.campaign import Campaign
from recon.catalog import HUNT_SKILLS, PHASES, catalog
from recon.cli import main
from recon.pipeline import Recon
from recon.report import write_reports
from recon.score import applicable_classes
from recon.skillmap import SKILLS_DIR, SKILLS_FOR_CLASS, skill_path, skills_for
from tests.test_recon import write_campaign

REPO = Path(__file__).resolve().parents[1]
# Imported mind-hunt authentication skills (licence/provenance/hard-limit pins apply);
# listed explicitly so a new original hunt skill is never treated as imported auth content.
AUTH_SKILLS = ["hunt-auth-bypass", "hunt-ato", "hunt-mfa-bypass", "hunt-oauth", "hunt-saml"]
ORIGINAL_HUNT_SKILLS = ["hunt-ssrf", "hunt-idor", "hunt-xss", "hunt-sqli", "hunt-csrf"]
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "h1_sample"}
REPORT_INDEX = REPO / "vault" / "_data" / "reports-merged.csv"


def frontmatter(text):
    """Minimal YAML subset: top-level `key: value` plus one level of nested mapping."""
    if not text.startswith("---\n"):
        raise ValueError("missing frontmatter")
    block = text[4:text.index("\n---\n", 4)]
    data, parent = {}, None
    for line in block.splitlines():
        if not line.strip():
            continue
        nested = line.startswith("  ")
        key, sep, value = line.strip().partition(":")
        if not sep:
            raise ValueError(f"bad frontmatter line: {line!r}")
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if nested and parent is not None:
            data[parent][key] = value
        elif value:
            data[key], parent = value, None
        else:
            data[key], parent = {}, key
    return data


def skill_dirs():
    return sorted(p for p in SKILLS_DIR.iterdir() if p.is_dir())


def skill_text(skill_id):
    return skill_path(skill_id).read_text(encoding="utf-8")


class SkillFolderTests(unittest.TestCase):
    def test_every_skill_lives_in_the_one_folder(self):
        self.assertEqual(SKILLS_DIR, REPO / ".claude" / "skills")
        self.assertFalse((REPO / "recon" / "skills").exists(), "old recon/skills folder must be gone")
        found = []
        for current, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            found += [Path(current) / f for f in files if f == "SKILL.md"]
        self.assertTrue(found)
        for path in found:
            self.assertEqual(path.parent.parent, SKILLS_DIR, f"{path} is outside {SKILLS_DIR}")

    def test_no_flat_markdown_at_the_folder_root(self):
        # OpenCode registers root-level *.md files in a skills source as skills.
        self.assertEqual([p.name for p in SKILLS_DIR.glob("*.md")], [])

    def test_every_skill_is_well_formed(self):
        for directory in skill_dirs():
            with self.subTest(skill=directory.name):
                text = (directory / "SKILL.md").read_text(encoding="utf-8")
                # Plain YAML scalars break on ": ", " #" or a leading indicator; a skill whose
                # frontmatter fails to parse is silently not advertised by the harness.
                for line in text[4:text.index("\n---\n", 4)].splitlines():
                    value = line.strip().partition(":")[2].strip()
                    if value and not (value.startswith('"') and value.endswith('"')):
                        self.assertNotRegex(value, r": | #|^[`@!&*|>%{\[,'\"?]", line)
                meta = frontmatter(text)
                self.assertEqual(meta.get("name"), directory.name)
                self.assertRegex(directory.name, r"^[a-z0-9]+(-[a-z0-9]+)*$")
                self.assertLessEqual(len(directory.name), 64)
                self.assertTrue(meta.get("description"))
                self.assertLessEqual(len(meta["description"]), 1024)

    def test_catalog_lists_exactly_the_folder(self):
        listed = {key for key, *_ in PHASES} | {key for key, _ in HUNT_SKILLS}
        self.assertEqual({d.name for d in skill_dirs()}, listed)
        data = catalog()
        for entry in data["phases"] + data["hunt_skills"]:
            self.assertTrue((REPO / entry["guide"]).is_file(), entry["guide"])
        self.assertEqual(data["execution"]["skill_dir"], ".claude/skills")
        self.assertEqual(data["execution"]["hunt_skills"], 10)
        self.assertEqual({key for key, _ in HUNT_SKILLS},
                         set(AUTH_SKILLS) | set(ORIGINAL_HUNT_SKILLS))
        self.assertEqual(data["execution"]["capability_guides"], 8)

    def test_nothing_points_outside_bugvault(self):
        existing = {d.name for d in skill_dirs()}
        forbidden = ("Downloads", "/Users/", "security-arsenal", "triage-validation",
                     "web2-vuln-classes", "web2-recon", "methodology-bible")
        for directory in skill_dirs():
            text = (directory / "SKILL.md").read_text(encoding="utf-8")
            with self.subTest(skill=directory.name):
                for needle in forbidden:
                    self.assertNotIn(needle, text)
                for ref in set(re.findall(r"\bhunt-[a-z0-9]+(?:-[a-z0-9]+)*", text)):
                    self.assertIn(ref, existing, f"{directory.name} references missing skill {ref}")

    def test_referenced_cli_commands_exist(self):
        seen = set()
        for directory in skill_dirs():
            text = (directory / "SKILL.md").read_text(encoding="utf-8")
            for cmd, action in re.findall(r"python3 -m recon ([a-z][a-z-]*)(?: ([a-z]+)\b)?", text):
                seen.add((cmd, action if cmd in ("finding", "fact") else ""))
        self.assertIn(("send", ""), seen)
        for cmd, action in sorted(seen):
            argv = [cmd, action, "--help"] if action else [cmd, "--help"]
            with self.subTest(argv=argv), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as done:
                    main(argv)
                self.assertEqual(done.exception.code, 0, f"recon {' '.join(argv)} is not a command")


class AuthSkillPolicyTests(unittest.TestCase):
    """The imported skills must follow BugVault's limits, not the upstream shortcuts."""

    def test_unbounded_or_out_of_band_shortcuts_are_absent(self):
        patterns = {
            "full OTP keyspace": r"seq\s+-w\s+0{4,}\s+9{4,}|000000-999999",
            "proxy/IP rotation": r"proxychains|rotat\w* (?:source )?IPs?\b",
            "breach-corpus spraying": r"breach corpus|password-spray",
            "own HTTP client": r"\baiohttp\b|\bcurl\s+(?:-|[\"']?https?://)|\bffuf\s+-u\b",
        }
        for skill in AUTH_SKILLS:
            text = skill_text(skill)
            for label, pattern in patterns.items():
                with self.subTest(skill=skill, rule=label):
                    self.assertIsNone(re.search(pattern, text, re.I))

    def test_bugvault_rules_are_present(self):
        for skill in AUTH_SKILLS:
            text = skill_text(skill)
            with self.subTest(skill=skill):
                self.assertIn("python3 -m recon send", text)
                self.assertIn("allowed_methods", text)
                self.assertRegex(text, r"(?i)test accounts?")
                self.assertRegex(text, r"validator|reportability gate")
                self.assertIn("## Hard limits", text)
                self.assertRegex(text, r"--class (ato|mfa-bypass|oauth|saml)\b")

    def test_full_active_method_grant_is_documented(self):
        for skill in ("scope-policy", "hunt-auth-bypass"):
            text = skill_text(skill)
            with self.subTest(skill=skill):
                self.assertIn('["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"]', text)
                self.assertIn("disposable", text)
        self.assertIn("--allow-method OPTIONS --allow-method DELETE", skill_text("scope-policy"))

    def test_burp_handoffs_share_one_reference_and_do_not_claim_integration(self):
        path = SKILLS_DIR / "scope-policy" / "references" / "burp-workflow.md"
        workflow = path.read_text(encoding="utf-8")
        for skill in ("hunt-auth-bypass", "hunt-mfa-bypass", "hunt-saml"):
            self.assertIn(path.relative_to(REPO).as_posix(), skill_text(skill))
        for needle in ("manual-only", "Send group in parallel", "last-byte", "single-packet",
                       "Collaborator (Burp Pro)", "JWKS", "negative control", "not built",
                       "does not", "budget", "HAR import", "Turbo Intruder"):
            self.assertIn(needle, workflow)
        self.assertIn("concurrency", skill_text("hunt-mfa-bypass"))
        self.assertIn("known test code", skill_text("hunt-mfa-bypass"))
        self.assertIn("DNS lookup alone does not prove", skill_text("hunt-saml"))
        for tool in catalog()["tools"]:
            if tool["name"] in ("Burp Repeater", "Burp Intruder"):
                self.assertEqual(tool["integration"], "manual-only")
            if tool["name"] in ("Burp MCP", "Burp Collaborator"):
                self.assertEqual(tool["integration"], "mcp-external")

    def test_generated_briefs_do_not_authorize_external_burp_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            camp = write_campaign(Path(directory) / "camp", "active", [], in_scope=["acme.test"])
            for role in ("hunter", "validator", "reporter"):
                with self.subTest(role=role):
                    text = render(camp, role)
                    self.assertIn("Burp Repeater/Intruder/Collaborator workflows are operator-only", text)
                    self.assertIn("not approved agent executors under this brief", text)
                    self.assertIn("Relevant history/evidence reads", text)
                    self.assertIn("dedicated visible browser and its proxy takes priority", text)

    def test_license_and_provenance_are_recorded(self):
        for skill in AUTH_SKILLS:
            with self.subTest(skill=skill):
                meta = frontmatter(skill_text(skill))
                digest = meta["metadata"]["source-sha256"]
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                self.assertEqual(meta["metadata"]["source"], f"mind-hunt skills/{skill}")
                notice = (SKILLS_DIR / skill / "LICENSE.txt").read_text(encoding="utf-8")
                for needle in ("MIT License", "Copyright (c) 2026 MindflareX", digest,
                               "The above copyright notice and this permission notice"):
                    self.assertIn(needle, notice)

    def test_reference_cases_match_the_report_index(self):
        if not REPORT_INDEX.is_file():
            self.skipTest("vault/_data/reports-merged.csv not built")
        with REPORT_INDEX.open(newline="", encoding="utf-8") as handle:
            index = {row["id"]: row for row in csv.DictReader(handle)}
        checked = 0
        for skill in AUTH_SKILLS:
            for rid, amount in re.findall(r"^\| #(\d+) \|.*\| (\$[\d,]+|unknown) \|$",
                                          skill_text(skill), re.M):
                with self.subTest(skill=skill, report=rid):
                    self.assertIn(rid, index, f"#{rid} is not in BugVault's report index")
                    row = index[rid]
                    recorded = {float(v) for v in (row["source_bounty_amount"],
                                                   row["codebygk_bounty_amount"]) if v}
                    if amount == "unknown":
                        self.assertEqual(recorded, set())
                    else:
                        self.assertIn(float(amount[1:].replace(",", "")), recorded)
                    checked += 1
        self.assertGreaterEqual(checked, 15)


class CampaignExecutionPermissionTests(unittest.TestCase):
    def test_shared_instructions_use_standing_permissions_not_scanner_bans(self):
        paths = [REPO / "AGENTS.md", REPO / "recon/prompts/hunter.md",
                 SKILLS_DIR / "scope-policy/SKILL.md",
                 SKILLS_DIR / "scope-policy/references/browser-workflow.md",
                 skill_path("hunt-idor")]
        for path in paths:
            text = " ".join(path.read_text(encoding="utf-8").split())
            with self.subTest(path=path):
                self.assertIn("standing campaign execution plan", text)
                self.assertIn("operator-run scanners", text.lower())
                self.assertNotIn("no scanners", text.lower())
                self.assertNotIn("without a new explicit operator exception", text)
                self.assertIn("scope/rate/budget", text)

    def test_scanner_permissions_stay_conditional_in_every_brief(self):
        with tempfile.TemporaryDirectory() as directory:
            camp = write_campaign(Path(directory) / "camp", "active", [], in_scope=["acme.test"])
            for role in ("hunter", "validator", "reporter"):
                text = render(camp, role)
                with self.subTest(role=role):
                    for needle in ("Operator-run scanners are permitted when",
                                   "program's written rules", "tool/version", "exclusions",
                                   "concurrency", "time window", "stop conditions",
                                   "Without that grant, do not scan",
                                   "recon has no external scanner executor",
                                   "manual scope, method, rate and shared-budget enforcement",
                                   "never overrides a failed scope/rate/budget check",
                                   "tool approval prompts still apply"):
                        self.assertIn(needle, text)

    def test_rule_text_does_not_grant_write_methods(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "camp"
            write_campaign(root, "active", [], in_scope=["acme.test"])
            config = root / "scope.json"
            raw = json.loads(config.read_text())
            raw["rules"] = ["Program permits scanners and writes to disposable test objects."]
            config.write_text(json.dumps(raw))
            camp = Campaign.load(root)
            text = render(camp, "hunter")
            self.assertEqual(camp.policy.allowed_methods, ["GET", "HEAD"])
            self.assertIn(raw["rules"][0], text)
            self.assertIn("Granted HTTP methods for this campaign: GET, HEAD.", text)
            self.assertIn("Pre-approval does not add an exploit or mutation executor", text)
            self.assertNotIn("Write methods are authorized for in-scope", text)

    def test_granted_writes_use_disposable_resources_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "camp"
            write_campaign(root, "active", [], in_scope=["acme.test"])
            config = root / "scope.json"
            raw = json.loads(config.read_text())
            raw["policy"]["allowed_methods"] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
            raw["rules"] = ["Program permits state-changing tests on disposable test objects."]
            config.write_text(json.dumps(raw))
            camp = Campaign.load(root)
            for role in ("hunter", "validator", "reporter"):
                text = render(camp, role)
                with self.subTest(role=role):
                    self.assertIn("Write methods are authorized for in-scope state-changing tests", text)
                    self.assertIn("disposable operator-owned test resources", text)
                    self.assertIn("before/after evidence and agreed cleanup", text)
                    self.assertIn("scope-, rate- and budget-checked", text)
                    self.assertNotIn("Pre-approval does not add an exploit or mutation executor", text)
            hunter = render(camp, "hunter")
            self.assertIn("A granted HTTP DELETE", hunter)
            self.assertIn("destructive SQL/OS commands", hunter)
            self.assertIn("use your own test accounts", hunter)


class IDORSkillPolicyTests(unittest.TestCase):
    """Original BugVault skill: staged substitution depth with controls kept intact."""

    def setUp(self):
        self.text = skill_text("hunt-idor")
        self.directory = SKILLS_DIR / "hunt-idor"
        self.refs = "\n".join(p.read_text() for p in (self.directory / "references").glob("*.md"))

    def test_staged_depth_controls_and_limits_are_explicit(self):
        for needle in ("Stage 1", "Stage 5", "request-shape", "negative control", "marker",
                       "Hard limits", "disposable", "real users", "real-user",
                       "dedicated browser through Burp", "python3 -m recon send",
                       "comparison groups", "three-attempt"):
            self.assertIn(needle.lower(), (self.text + self.refs).lower())

    def test_chain_targets_use_supported_relations(self):
        self.assertIn("idor_candidates", self.text)
        for relation in ("yields-access", "yields-token", "escalates-via"):
            self.assertIn(relation, self.text)
        from recon.findings import RELATIONS
        for relation in re.findall(r"`(yields-[a-z]+|escalates-via|pivots-to|enables)`", self.text):
            self.assertIn(relation, RELATIONS)

    def test_provenance_is_pinned_and_unverified_claims_excluded(self):
        techniques = (self.directory / "references" / "techniques.md").read_text()
        for blob in ("e6f8cef68db2eb35b253acbf8eb4e0d988549a97",
                     "d958e7c646181cc2e60a4996f53b443360c6086b",
                     "27d41a5f249e1d938b687cf9c2724f1a7680df29",
                     "0accf5fdc71ec7f03273aebb99268a8609f8dfd4"):
            self.assertIn(blob, techniques)
        self.assertIn("no IDOR file", techniques)
        self.assertIn("unverified", techniques)

    def test_id_traffic_seeds_coverage_that_names_the_skill(self):
        self.assertIn("idor-bola", applicable_classes(
            {"value": "https://acme.test/api/orders", "attrs": {"id_params": ["orderId"]}}))
        with tempfile.TemporaryDirectory() as directory:
            camp = write_campaign(Path(directory) / "camp", "active", [], in_scope=["acme.test"])
            ctx = Recon(camp, log=lambda _: None)
            try:
                ctx.add_endpoint("https://acme.test/api/orders", "har", method="GET",
                                 params=["orderId"], extra={"id_params": ["orderId"]})
                ctx.refresh_coverage()
                coverage = next(p for p in write_reports(ctx) if p.name == "coverage.md")
                rows = coverage.read_text(encoding="utf-8").splitlines()
            finally:
                ctx.store.close()
        idor = [r for r in rows if "/api/orders" in r and "| idor-bola |" in r]
        self.assertTrue(idor and idor[0].rstrip().endswith("| hunt-idor |"))


class TriggerTests(unittest.TestCase):
    """recon seeds the coverage row; coverage.md names the skill; the hunter brief loads it."""

    def test_auth_paths_seed_rows_that_point_to_existing_skills(self):
        cases = {
            "https://acme.test/login": "ato",
            "https://acme.test/api/v1/password/reset": "ato",
            "https://acme.test/api/mfa/verify": "mfa-bypass",
            "https://acme.test/oauth/authorize": "oauth",
            "https://acme.test/saml/acs": "saml",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                classes = applicable_classes({"value": url, "attrs": {}})
                self.assertIn(expected, classes)
                self.assertIn("ato", classes)
                for skill in skills_for(expected):
                    self.assertTrue(skill_path(skill).is_file(), skill)
        self.assertEqual(skills_for("ato"), ("hunt-auth-bypass", "hunt-ato"))
        self.assertEqual(skills_for("idor-bola"), ("hunt-idor",))
        mapped = {skill for skills in SKILLS_FOR_CLASS.values() for skill in skills}
        self.assertEqual(mapped, {key for key, _ in HUNT_SKILLS})

    def test_coverage_report_and_hunter_brief_name_the_skill(self):
        with tempfile.TemporaryDirectory() as directory:
            camp = write_campaign(Path(directory) / "camp", "active", [], in_scope=["acme.test"])
            ctx = Recon(camp, log=lambda _: None)
            try:
                ctx.add_endpoint("https://acme.test/login", "html", method="GET")
                ctx.add_endpoint("https://acme.test/api/mfa/verify", "js", method="POST")
                ctx.refresh_coverage()
                coverage = next(p for p in write_reports(ctx) if p.name == "coverage.md")
                rows = coverage.read_text(encoding="utf-8").splitlines()
            finally:
                ctx.store.close()
            login = [r for r in rows if "/login" in r and "| ato |" in r]
            self.assertTrue(login and login[0].rstrip().endswith("| hunt-auth-bypass, hunt-ato |"))
            mfa = [r for r in rows if "/api/mfa/verify" in r and "| mfa-bypass |" in r]
            self.assertTrue(mfa and "hunt-mfa-bypass" in mfa[0])
            csrf_row = [r for r in rows if "/api/mfa/verify" in r and "| csrf |" in r]
            self.assertTrue(csrf_row and csrf_row[0].rstrip().endswith("| hunt-csrf |"))
            unmapped = [r for r in rows if "/api/mfa/verify" in r and "| mass-assignment |" in r]
            self.assertTrue(unmapped and unmapped[0].rstrip().endswith("| - |"))
            brief = render(camp, "hunter")
            for needle in (".claude/skills", "`hunt-auth-bypass`", f"recon send {camp.name}"):
                self.assertIn(needle, brief)


if __name__ == "__main__":
    unittest.main()
