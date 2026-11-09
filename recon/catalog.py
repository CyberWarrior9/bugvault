"""Executable capability inventory. Availability checks never run binaries or use the network."""
from __future__ import annotations

import importlib.util
import shutil
from typing import Any, Dict

from .ingest import FORMATS
from .pipeline import JOB_NEEDS

ARTEX_COMMIT = "9bf5d816aeb361d79de874fcdbeeb0de31bd83f2"
PHASES = (
    ("scope-policy", "Authorization and policy", [], "offline", "scope.json; deny rules; budgets"),
    ("passive-discovery", "L0 passive discovery", ["crtsh", "wayback"], "passive", "domains; archive references"),
    ("service-mapping", "L1 service mapping", ["probe"], "active", "IP associations; origins; fingerprints"),
    ("static-api-mapping", "L2 static surface mapping", ["wellknown", "jsharvest", "jsparse", "mapparse"],
     "active", "endpoint families; methods; parameter names; routes; code references"),
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
    ("dig", "dig", "optional-native", "service-mapping", "CNAME lookup only"),
    ("Playwright Python", None, "optional-native", "synthetic-ui-mapping", "Requires Python package and Chromium"),
    ("HAR", None, "offline-import", "captured-auth-mapping", "DevTools/Burp/Caido HAR; no extension installed"),
    ("BBOT", "bbot", "offline-import", "passive-discovery,service-mapping,static-api-mapping", "JSON/JSONL surface events only"),
    ("subfinder", "subfinder", "offline-import", "passive-discovery", "Text hosts or JSONL host objects"),
    ("httpx (ProjectDiscovery)", "httpx", "offline-import", "service-mapping", "JSONL url/status_code/tech; PATH identity unverified"),
    ("Katana", "katana", "offline-import", "static-api-mapping", "JSONL request.endpoint and method"),
    ("ScopeSentry", None, "offline-import", "service-mapping,static-api-mapping", "JSON export only; no MCP/API integration"),
    ("searchsploit", "searchsploit", "optional-native", "inventory-handoff", "Local Exploit-DB search on fingerprinted versions; `lookup`"),
    ("Sploitus", None, "native", "inventory-handoff", "Exploit search API; receives product+version only; `lookup`"),
    ("CISA KEV", None, "native", "inventory-handoff", "Known-exploited CVE feed, cached 24 h; `lookup`"),
    ("Nmap", "nmap", "manual-only", "service-mapping", "No port-scanner execution or XML adapter"),
    ("ffuf", "ffuf", "manual-only", "static-api-mapping", "No fuzzing executor or output adapter"),
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
                      "har_import_adapters": 1, "capability_guides": len(PHASES),
                      "automatically_invoked_llm_skills": 0,
                      "model_routing": "not implemented; no Qwen/GLM/OpenAI calls"},
        "artex_topology": {"planner": 1, "default_workers": 3, "ongoing_instances_default": 4,
                           "goals_decomposer": "one-shot additional call",
                           "default_recon_skill": "api-recon",
                           "optional_skills": ["bbot-recon", "scopesentry", "playwright-cli"]},
        "phases": [{"id": key, "name": name, "handlers": handlers, "need": need,
                    "outputs": outputs, "guide": f"recon/skills/{key}/SKILL.md"}
                   for key, name, handlers, need, outputs in PHASES],
        "job_needs": dict(JOB_NEEDS), "tools": tools,
        "availability": {"playwright_python": importlib.util.find_spec("playwright") is not None,
                         "chromium_launch_verified": False,
                         "note": "PATH/package presence only; no version, credentials, service or launch check"},
    }


def render_catalog(data: Dict[str, Any]) -> str:
    lines = ["# Recon capability catalog", "", str(data["execution"]), "", "## Phases"]
    for phase in data["phases"]:
        lines.append(f"- {phase['name']}: {phase['outputs']} [{phase['need']}]")
    lines += ["", "## Tools (availability does not imply an executor)"]
    for tool in data["tools"]:
        availability = tool["path"] or ("not in PATH" if tool["command"] else "see requirements")
        lines.append(f"- {tool['name']}: {tool['integration']}; {availability}. {tool['note']}")
    return "\n".join(lines)
