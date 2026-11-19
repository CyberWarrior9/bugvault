"""BugVault skills: one folder, and which skill each coverage bug class points to.

Every skill lives in `.claude/skills/<id>/SKILL.md` at the repository root. OpenCode
and Claude Code discover that folder in sessions opened inside this repository and
offer a skill to the model when a task matches its description. The recon engine
never loads or runs a skill; it only names the skill to load beside the coverage
rows it seeds.

Seeding is **not** only in `score.py`. Evidence-based classes seed from the module
that observes the evidence, so `applicable_classes` alone is not a complete answer
to "what gets seeded" -- see `SEEDED_BY` below, which `tests/test_recon_seeders.py`
keeps in step with the routing table.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple

REPO = Path(__file__).resolve().parents[1]
SKILLS_DIR_REL = ".claude/skills"
SKILLS_DIR = REPO / SKILLS_DIR_REL

# Coverage class -> skills to load, primary first.
SKILLS_FOR_CLASS: Dict[str, Tuple[str, ...]] = {
    "cloud-misconfiguration": ("hunt-cloud-misconfig",),
    "subdomain-takeover": ("hunt-takeover",),
    "ssrf": ("hunt-ssrf",),
    "idor-bola": ("hunt-idor",),
    "access-control": ("hunt-access-control",),
    "mass-assignment": ("hunt-access-control",),
    "xss": ("hunt-xss",),
    "html-injection": ("hunt-xss",),
    "sqli": ("hunt-sqli",),
    # Do not route SSTI to SQLi: expression evaluation needs its own proof standard.
    "ssti": ("hunt-ssti",),
    "csrf": ("hunt-csrf",),
    "file-upload": ("hunt-file-upload",),
    "info-disclosure": ("hunt-js-bundle",),
    "js-bundle": ("hunt-js-bundle",),
    "business-logic": ("hunt-business-logic",),
    "race-conditions": ("hunt-race-conditions",),
    # Rung and channel are separate axes here: a fetched DTD is not a file read.
    "xxe": ("hunt-xxe",),
    # Schema exposure only. Object substitution stays with hunt-idor and mutation
    # transport with hunt-csrf; a GraphQL endpoint seeds both graphql and idor-bola.
    "graphql": ("hunt-graphql",),
    "ato": ("hunt-auth-bypass", "hunt-ato"),
    "mfa-bypass": ("hunt-mfa-bypass",),
    "oauth": ("hunt-oauth",),
    "saml": ("hunt-saml",),
}

# Which module seeds each coverage class. `score.py` applicable_classes is no longer
# the whole story: classes whose signal is observed evidence rather than an asset
# attribute seed from the module that observes it. Keep this in step with the
# routing table above -- `tests/test_recon_seeders.py` enforces that every routed
# class appears here, and that every entry names a module that exists.
SEEDED_BY: Dict[str, str] = {
    # score.py applicable_classes: seeded from asset attrs, params and methods
    "access-control": "score.py",
    "ato": "score.py",
    "business-logic": "score.py",
    "csrf": "score.py",
    "file-read": "score.py",
    "file-upload": "score.py",
    "graphql": "score.py",
    "html-injection": "score.py",
    "idor-bola": "score.py",
    "mass-assignment": "score.py",
    "mfa-bypass": "score.py",
    "oauth": "score.py",
    "open-redirect": "score.py",
    "race-conditions": "score.py",
    "saml": "score.py",
    "sqli": "score.py",
    "ssrf": "score.py",
    "ssti": "score.py",
    "xss": "score.py",
    "xxe": "score.py",
    # evidence-based: seeded by the module that observed the evidence
    "cloud-misconfiguration": "cloud.py",
    "info-disclosure": "jsintel.py",
    "js-bundle": "jsledger.py",
    "subdomain-takeover": "pipeline.py, takeover.py",
}

# Classes that exist only as finding labels and never as coverage rows. They reach
# the graph through `findings.py` CHAIN_HINTS, which iterates *findings* rather than
# coverage rows, so they need no seeding rule and must not be routed to a skill.
#   known-cve      created automatically by vulnintel.lookup (`fx.add(..., "known-cve")`)
#   cloud-metadata recorded by the operator when an SSRF case reaches the metadata
#                  service; the ssrf cloud/credential depth branches carry the work
FINDING_ONLY_CLASSES: Tuple[str, ...] = ("known-cve", "cloud-metadata")


def skills_for(bug_class: str) -> Tuple[str, ...]:
    return SKILLS_FOR_CLASS.get(bug_class, ())


def seeded_by(bug_class: str) -> str:
    """Which module seeds this coverage class, or '' if it is finding-only."""
    return SEEDED_BY.get(bug_class, "")


def skill_path(skill_id: str) -> Path:
    return SKILLS_DIR / skill_id / "SKILL.md"
