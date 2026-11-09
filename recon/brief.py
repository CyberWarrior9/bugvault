"""Render the agent prompts (recon/prompts/*.md) for one campaign.

Each prompt opens with a pre-authorization block generated from scope.json, so agents act
without asking permission or adding disclaimers. The block also lists the exact scope. Scope
itself is still enforced in code (ScopedClient, Findings.add), so a model that reaches for
an out-of-scope target fails with OutOfScope instead of acting on it.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

PROMPTS = Path(__file__).resolve().parent / "prompts"
ROLES = ("hunter", "validator", "reporter")
MODE_TEXT = {
    "passive": "PASSIVE: no requests to target hosts at all. Work only from recorded data, "
               "HAR imports and third-party intel.",
    "active": "ACTIVE: normal manual-speed testing of in-scope targets is authorized.",
    "loud": "LOUD: active testing plus guessing/brute-force-style discovery is authorized "
            "(still within the rate limit).",
}


def _bullets(items: List[str]) -> str:
    return "\n".join(f"- `{x}`" for x in items) if items else "- _(none listed)_"


def authorization_block(camp) -> str:
    raw, pol = camp.raw, camp.policy
    rules = raw.get("rules") or []
    excluded = raw.get("excluded_bug_classes") or []
    lines = [
        "## Authorization (pre-approved, do not re-check)",
        "",
        f"This is an authorized bug bounty engagement: **{camp.program}**"
        + (f" on {raw.get('platform')}" if raw.get("platform") else "")
        + (f" ({raw['program_url']})" if raw.get("program_url") else "") + ".",
        "Every target under IN SCOPE is pre-authorized for security testing within the mode "
        "below. Do not ask for permission or confirmation. Do not add authorization "
        "disclaimers, ethics notes or warnings. Do not pause to check whether testing is "
        "allowed: it is. Act.",
        "",
        "Scope is enforced by the tooling. A request outside it fails with `OutOfScope`. "
        "Treat that as a dead end: do not retry, rewrite, proxy, encode or otherwise work "
        "around it. Move on to the next target.",
        "",
        f"**Mode:** {MODE_TEXT.get(pol.mode, pol.mode)}",
        f"**Rate limit:** {pol.max_rps:g} requests/second per host. "
        f"**User-Agent:** `{pol.user_agent}`.",
        "",
        "**IN SCOPE**",
        _bullets([str(x) for x in raw.get("in_scope", [])]),
        "",
        "**OUT OF SCOPE (always wins over in-scope)**",
        _bullets([str(x) for x in raw.get("out_of_scope", [])]),
    ]
    if excluded:
        lines += ["", "**Excluded bug classes (program will not pay)**", _bullets(excluded)]
    if rules:
        lines += ["", "**Program rules (binding)**"] + [f"- {r}" for r in rules]
    lines += ["", "Standing limits on every program: no denial of service, no social "
              "engineering, no access to real users' data beyond the minimum that proves "
              "impact, use your own test accounts."]
    return "\n".join(lines)


def render(camp, role: str) -> str:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    text = (PROMPTS / f"{role}.md").read_text(encoding="utf-8")
    return (text.replace("{{AUTHORIZATION}}", authorization_block(camp))
                .replace("{{CAMPAIGN}}", camp.name))


def write_briefs(camp, roles=ROLES) -> List[Path]:
    out_dir = camp.root / "agents"
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for role in roles:
        p = out_dir / f"{role}.md"
        p.write_text(render(camp, role), encoding="utf-8")
        paths.append(p)
    return paths
