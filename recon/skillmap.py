"""BugVault skills: one folder, and which skill each coverage bug class points to.

Every skill lives in `.claude/skills/<id>/SKILL.md` at the repository root. OpenCode
and Claude Code discover that folder in sessions opened inside this repository and
offer a skill to the model when a task matches its description. The recon engine
never loads or runs a skill; it only names the skill to load beside the coverage
rows it seeds (`recon/score.py` applicable_classes -> `coverage.md`).
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Tuple

REPO = Path(__file__).resolve().parents[1]
SKILLS_DIR_REL = ".claude/skills"
SKILLS_DIR = REPO / SKILLS_DIR_REL

# Coverage class -> skills to load, primary first.
SKILLS_FOR_CLASS: Dict[str, Tuple[str, ...]] = {
    "ssrf": ("hunt-ssrf",),
    "idor-bola": ("hunt-idor",),
    "xss": ("hunt-xss",),
    "html-injection": ("hunt-xss",),
    "sqli": ("hunt-sqli",),
    "ssti": ("hunt-sqli",),
    "csrf": ("hunt-csrf",),
    "ato": ("hunt-auth-bypass", "hunt-ato"),
    "mfa-bypass": ("hunt-mfa-bypass",),
    "oauth": ("hunt-oauth",),
    "saml": ("hunt-saml",),
}


def skills_for(bug_class: str) -> Tuple[str, ...]:
    return SKILLS_FOR_CLASS.get(bug_class, ())


def skill_path(skill_id: str) -> Path:
    return SKILLS_DIR / skill_id / "SKILL.md"
