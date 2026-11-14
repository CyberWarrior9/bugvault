"""Executable capability inventory. Availability checks never run binaries or use the network."""
from __future__ import annotations

import importlib.util
import shutil
from typing import Any, Dict

from .ingest import FORMATS
from .pipeline import JOB_NEEDS
from .skillmap import SKILLS_DIR_REL, SKILLS_FOR_CLASS

ARTEX_COMMIT = "9bf5d816aeb361d79de874fcdbeeb0de31bd83f2"
# Hunting skills (same folder as the phase guides). Coverage classes come from SKILLS_FOR_CLASS.
HUNT_SKILLS = (
    ("hunt-ssrf", "SSRF: browser/Burp-only live workflow, attributed canaries, parser/redirect/DNS "
                  "matrix, scoped internal/cloud branches, offline case ledger and callback correlation"),
    ("hunt-idor", "IDOR/BOLA/BFLA: object/identity substitution across path/query/body/header/GraphQL, "
                  "HAR comparison groups, staged depth ladder with request-shape variants, vertical "
                  "and cross-tenant checks, write proofs and chain targets"),
    ("hunt-xss", "XSS/HTML injection: input census with probe receipts, per-field context map, "
                 "probe-ladder WAF/filter mapping before variant design, reflected/stored/DOM/blind "
                 "variants, marker-execution proofs and chain targets"),
    ("hunt-sqli", "SQL injection: input census, detection-mapping ladder, error/boolean/time/OOB/"
                  "UNION/second-order variants with differential triples, minimal-extraction proofs "
                  "and gated chain targets"),
    ("hunt-csrf", "CSRF: per-origin action x context x case ledger (fieldless actions, GET "
                  "mutations, GraphQL operations and realtime handshakes included), fifteen case "
                  "families from token channels and SameSite delivery to client-side, SSO, "
                  "WebSocket and BFF defenses, browser-initiated exercises and ATO chains"),
    ("hunt-auth-bypass", "Login bypass: missing auth, trusted headers/cookies, JWT, reset tokens, "
                         "magic links, session fixation, internal self-signup"),
    ("hunt-ato", "Account-takeover chain target: reset tokens, reset-link host poisoning, email change, "
                 "account linking, sensitive changes without re-authentication"),
    ("hunt-mfa-bypass", "MFA/2FA: enforcement gaps, step skip, OTP reuse, bounded rate-limit proof, "
                        "recovery codes, remember-device trust"),
    ("hunt-oauth", "OAuth/OIDC: redirect_uri, state, nonce, PKCE, response_type, token audience, "
                   "deep links"),
    ("hunt-saml", "SAML/SSO: signature wrapping and stripping, comment injection, audience, replay, XXE"),
)
PHASES = (
    ("scope-policy", "Authorization and policy", [], "offline", "scope.json; deny rules; budgets"),
    ("passive-discovery", "L0 passive discovery", ["crtsh", "wayback"], "passive", "domains; archive references"),
    ("service-mapping", "L1 service mapping", ["probe"], "active", "IP associations; origins; fingerprints"),
    ("static-api-mapping", "L2 static surface mapping", ["wellknown", "jsharvest", "jsparse", "mapparse"],
     "active", "endpoint families; methods; parameter names; routes; code references"),
    ("apk-static-mapping", "Mobile app static surface (external REA/JADX)", [], "offline external tool",
     "APK endpoints, old API versions, secrets, deep links; untrusted leads only"),
    ("synthetic-ui-mapping", "L3 optional synthetic UI mapping", ["runtime"], "active + runtime.enabled",
     "client-attempted calls; synthetic UI observations (not backend access)"),
    ("captured-auth-mapping", "L4 captured authenticated mapping", [], "offline HAR import",
     "separate account/role/tenant/workflow observations"),
    ("inventory-handoff", "Prioritization and handoff", [], "offline",
     "recon.md; coverage.md; intel.md; provenance; unvalidated leads"),
)

# All entries are explicit about integration, not merely names that happen to be in PATH.
TOOLS = (
    ("crt.sh", None, "native", "passive-discovery", "Certificate transparency HTTP source"),
    ("Wayback CDX", None, "native", "passive-discovery", "Archived URL HTTP source"),
    ("stdlib HTTP/DNS/parsers", None, "native", "service-mapping,static-api-mapping", "Python implementation"),
    ("dig", "dig", "optional-native", "service-mapping", "CNAME lookup; required for subdomain-takeover leads (a missing dig records collection gaps, not takeovers)"),
    ("Playwright Python", None, "optional-native", "synthetic-ui-mapping", "Requires Python package and Chromium"),
    ("HAR", None, "offline-import", "captured-auth-mapping", "DevTools/Burp/Caido HAR; no extension installed"),
    ("Burp Save-items export", None, "offline-import", "captured-auth-mapping",
     "recon import-burp: XML/JSON export or one raw request; header/cookie names only "
     "(values dropped); stored responses searchable by the canary trace"),
    ("OpenAPI/Swagger spec", None, "offline-import", "static-api-mapping",
     "recon import-openapi: operator-supplied JSON spec; declared fields with exact "
     "locations; the spec is never fetched"),
    ("BBOT", "bbot", "offline-import", "passive-discovery,service-mapping,static-api-mapping", "JSON/JSONL surface events only"),
    ("subfinder", "subfinder", "offline-import", "passive-discovery", "Text hosts or JSONL host objects"),
    ("httpx (ProjectDiscovery)", "httpx", "offline-import", "service-mapping", "JSONL url/status_code/tech; PATH identity unverified"),
    ("Katana", "katana", "offline-import", "static-api-mapping", "JSONL request.endpoint and method"),
    ("ScopeSentry", None, "offline-import", "service-mapping,static-api-mapping", "JSON export only; no MCP/API integration"),
    ("searchsploit", "searchsploit", "optional-native", "inventory-handoff", "Local Exploit-DB search on fingerprinted versions; `lookup`"),
    ("Sploitus", None, "native", "inventory-handoff", "Exploit search API; receives product+version only; `lookup`"),
    ("CISA KEV", None, "native", "inventory-handoff", "Known-exploited CVE feed, cached 24 h; `lookup`"),
    ("Response predicate checker", None, "native", "inventory-handoff", "Offline status/header/raw-byte checks; not vulnerability confirmation"),
    ("SSRF workflow", None, "native-offline", "hunt-ssrf", "recon ssrf plan/record/status/correlate: offline matrix, hashed artifacts and interaction correlation; no traffic generator or automatic finding verdict"),
    ("Chain todolist", None, "native-offline", "inventory-handoff", "recon chain status/add: cross-class ready/waiting/proven steps over findings and validated custom chains; orders the hunt, executes nothing"),
    ("CSRF action ledger", None, "native-offline", "hunt-csrf", "recon csrf sync/plan/record/status/verify: per-origin action x context x case inventory with facet-scoped reopening, hash-bound browser-attempt artifacts and coarse-coverage conflict listing; sends no traffic, runs no browser or scanner"),
    ("Input census", None, "native-offline", "hunt-xss,hunt-sqli,hunt-idor", "recon inputs: per-endpoint field inventory with locations, accounts, sensitive-name flags, coverage join and stored-probe receipts; read-only, never guesses hidden params"),
    ("Burp MCP", None, "mcp-external", "captured-auth-mapping,inventory-handoff", "Project opencode.json/.mcp.json share localhost:9876/mcp across tool-capable models; 27 tools discovered on 2026-11-12; not a recon-enforced executor"),
    ("Burp Repeater", None, "manual-only", "hunt-mfa-bypass", "MCP can prepare tabs, but has no parallel-group send; no synchronized or shared-budget executor; see .claude/skills/scope-policy/references/burp-workflow.md"),
    ("Burp Intruder", None, "manual-only", "hunt-mfa-bypass", "MCP can prepare a tab, not run an attack; concurrency is not synchronization; no recon executor/result adapter"),
    ("Burp Collaborator", None, "mcp-external", "hunt-auth-bypass,hunt-saml,hunt-ssrf", "MCP exposes payload generation and interaction polling (operator approval); no raw-export/native-fact importer; ssrf correlate requires manual normalization; callbacks do not prove key trust or impact"),
    ("Nmap", "nmap", "manual-only", "service-mapping", "No port-scanner execution or XML adapter"),
    ("ffuf", "ffuf", "manual-only", "static-api-mapping", "No fuzzing executor or output adapter"),
    ("REA", "rea", "manual-only", "apk-static-mapping", "Reverse-engineering MCP/CLI (npx rea-agents); local static APK/JS/.NET/binary analysis; no import adapter yet; see docs/rea-analysis.md"),
    ("JADX (REA provider)", "jadx", "manual-only", "apk-static-mapping", "Android decompilation under REA; full JDK required; not invoked here"),
    ("adb (REA device analysis)", "adb", "manual-only", "apk-static-mapping", "Owned emulators/hardware only; runtime capture runs outside the scoped egress client"),
    ("dnsx", "dnsx", "reference-only", "service-mapping", "ARTEX Go enrichment library; not integrated here"),
    ("wafw00f", "wafw00f", "reference-only", "service-mapping", "ARTEX BBOT module; native lightweight signatures here"),
    ("paramminer_getparams", None, "reference-only", "static-api-mapping", "BBOT module, not an independent BugVault handler"),
    ("sslcert", None, "reference-only", "service-mapping", "BBOT module, not an independent BugVault handler"),
    ("gowitness", "gowitness", "reference-only", "service-mapping", "BBOT screenshot module; not integrated"),
    ("lightfuzz", None, "hunting-only", "outside-recon", "BBOT active testing module; never dispatched here"),
    ("Nuclei", "nuclei", "hunting-only", "outside-recon", "No template execution; scanner findings not confirmation"),
    ("Dalfox", "dalfox", "hunting-only", "outside-recon", "Not part of recon execution"),
    ("sqlmap", "sqlmap", "hunting-only", "outside-recon", "Not part of recon execution"),
    ("curl", "curl", "reference-only", "manual", "ARTEX shell utility; not invoked by this engine"),
    ("wget", "wget", "reference-only", "manual", "ARTEX shell utility; not invoked by this engine"),
    ("whois", "whois", "reference-only", "passive-discovery", "Not invoked by this engine"),
    ("ping", "ping", "reference-only", "service-mapping", "Not invoked by this engine"),
    ("netcat", "nc", "reference-only", "manual", "Not invoked by this engine"),
    ("telnet", "telnet", "reference-only", "manual", "Not invoked by this engine"),
    ("Playwright MCP/CLI", "playwright-cli", "reference-only", "synthetic-ui-mapping", "ARTEX browser support; Python API used here instead"),
    ("ARTEX traffic extension", None, "reference-only", "captured-auth-mapping", "Not ported; use offline HAR export"),
)


def catalog() -> Dict[str, Any]:
    tools = []
    for name, command, integration, phases, note in TOOLS:
        tools.append({"name": name, "command": command, "integration": integration,
                      "phases": phases.split(","), "note": note,
                      "path": shutil.which(command) if command else None})
    return {
        "schema_version": 1,
        "artex_reference_commit": ARTEX_COMMIT,
        "execution": {"llm_agents": 0, "deterministic_schedulers": 1, "concurrent_workers": 1,
                      "job_handlers": len(JOB_NEEDS), "scanner_import_adapters": len(FORMATS),
                      "har_import_adapters": 1, "burp_import_adapters": 1,
                      "spec_import_adapters": 1, "capability_guides": len(PHASES),
                      "hunt_skills": len(HUNT_SKILLS),
                      "automatically_invoked_llm_skills": 0,
                      "skill_dir": SKILLS_DIR_REL,
                      "skill_invocation": "the recon engine loads no skills; OpenCode and Claude Code "
                                          "advertise .claude/skills in sessions inside this repository "
                                          "and the model loads one when a task matches its description",
                      "manual_request_executor": "recon send (scope, method grant, rate, budgets, pinned egress)",
                      "model_routing": "not implemented; no model-provider calls"},
        "artex_topology": {"planner": 1, "default_workers": 3, "ongoing_instances_default": 4,
                           "goals_decomposer": "one-shot additional call",
                           "default_recon_skill": "api-recon",
                           "optional_skills": ["bbot-recon", "scopesentry", "playwright-cli"]},
        "phases": [{"id": key, "name": name, "handlers": handlers, "need": need,
                    "outputs": outputs, "guide": f"{SKILLS_DIR_REL}/{key}/SKILL.md"}
                   for key, name, handlers, need, outputs in PHASES],
        "hunt_skills": [{"id": key, "summary": summary, "guide": f"{SKILLS_DIR_REL}/{key}/SKILL.md",
                         "coverage_classes": sorted(c for c, ids in SKILLS_FOR_CLASS.items() if key in ids)}
                        for key, summary in HUNT_SKILLS],
        "job_needs": dict(JOB_NEEDS), "tools": tools,
        "availability": {"playwright_python": importlib.util.find_spec("playwright") is not None,
                         "chromium_launch_verified": False,
                         "note": "PATH/package presence only; no version, credentials, service or launch check"},
    }


def render_catalog(data: Dict[str, Any]) -> str:
    lines = ["# Recon capability catalog", "", str(data["execution"]), "", "## Phases"]
    for phase in data["phases"]:
        lines.append(f"- {phase['name']}: {phase['outputs']} [{phase['need']}]")
    lines += ["", f"## Skills (all in {data['execution']['skill_dir']}/)"]
    for phase in data["phases"]:
        lines.append(f"- {phase['id']}: recon phase guide")
    for skill in data["hunt_skills"]:
        classes = ", ".join(skill["coverage_classes"]) or "none"
        lines.append(f"- {skill['id']}: {skill['summary']} [coverage: {classes}]")
    lines += ["", "## Tools (availability does not imply an executor)"]
    for tool in data["tools"]:
        availability = tool["path"] or ("not in PATH" if tool["command"] else "see requirements")
        lines.append(f"- {tool['name']}: {tool['integration']}; {availability}. {tool['note']}")
    return "\n".join(lines)
