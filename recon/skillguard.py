"""Skill-file integrity: give SKILL.md content a runtime consequence.

The problem this closes: no engine gate reads a `SKILL.md` at runtime. `policy.allows`,
`Scope.check`, `RequestBudget`, the factcheck predicates and `toolexec` pacing all
refuse mechanically, in code, regardless of what a skill says. That is correct for
*enforcement* -- prose must never become policy -- but it means a skill can lose or
invert its scope-and-limits language and nothing notices until a human reads the file.

So this records a digest per skill and reports drift. It does NOT parse prose as policy.
The engine keeps refusing on its own terms; this only answers "is the text the model
will read still the text that was reviewed?"

Two kinds of drift, deliberately distinguished:

  * `content-changed` -- the digest moved. Normal: skills get edited. Informational.
  * `marker-lost`     -- a guardrail phrase occurs FEWER times than when recorded.
                         This is the one with safety consequence, because every phrase
                         in GUARD_MARKERS states who may be tested or through which
                         channel. A rewrite that drops "## Hard limits" or turns
                         "Do not read other users' files" into "Do read ..." shows up
                         here and nowhere else in the engine.

Marker counting is deliberately crude -- substring occurrences, case-folded. It cannot
understand a sentence, and it is not trying to. A count that goes down is a prompt to
read the diff, not a verdict about intent.

Default posture is REPORT. `verify(strict=True)` is what refuses, so adopting this does
not break a working tree whose skills are mid-edit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO / ".claude" / "skills"
MANIFEST = SKILLS_DIR / ".integrity.json"
SCHEMA_VERSION = 1

# Phrases whose absence changes what a model believes it may do. These are the same
# ones the skill-policy tests assert, so the two agree by construction rather than by
# coincidence: if a test starts failing, the marker count here moves too.
GUARD_MARKERS: Tuple[str, ...] = (
    "## hard limits",
    "scope-policy",
    "scope/rate/budget",
    "dedicated browser through burp",
    "no real money",
    "real-user",
    "do not",
    "never",
    "owned",
    "operator-owned",
)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _markers(text: str) -> Dict[str, int]:
    low = text.lower()
    return {m: low.count(m) for m in GUARD_MARKERS if low.count(m)}


def skill_files() -> List[Path]:
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(p for p in SKILLS_DIR.glob("*/SKILL.md") if p.is_file())


def snapshot() -> Dict[str, Any]:
    """Current state of every skill, as recordable facts."""
    out: Dict[str, Any] = {}
    for path in skill_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            out[path.parent.name] = {"unreadable": str(exc)[:200]}
            continue
        out[path.parent.name] = {"sha256": _digest(text), "bytes": len(text.encode("utf-8")),
                                 "markers": _markers(text)}
    return out


def load_manifest() -> Optional[Dict[str, Any]]:
    if not MANIFEST.is_file():
        return None
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and "skills" in data else None


def record(note: str = "") -> Dict[str, Any]:
    """Write the current state as the reviewed baseline."""
    data = {"schema_version": SCHEMA_VERSION, "note": note,
            "policy": "digest and guardrail-marker counts only; prose is never parsed as "
                      "policy, and engine gates do not consult this file",
            "markers_tracked": list(GUARD_MARKERS),
            "skills": snapshot()}
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return data


def verify(strict: bool = False) -> Dict[str, Any]:
    """Compare the tree against the recorded baseline.

    Returns a report. `ok` is False when any drift exists; `blocking` is False unless
    strict is set AND a marker was lost -- a content change alone never blocks, because
    editing a skill is normal work.
    """
    base = load_manifest()
    now = snapshot()
    if base is None:
        return {"ok": False, "blocking": False, "state": "no-baseline",
                "detail": f"no baseline at {MANIFEST.relative_to(REPO)}; "
                          "run `recon skills record` once the skills are in a reviewed state",
                "drifts": []}

    recorded: Dict[str, Any] = base.get("skills") or {}
    drifts: List[Dict[str, Any]] = []

    for name in sorted(set(recorded) | set(now)):
        was, isnow = recorded.get(name), now.get(name)
        if was is None:
            drifts.append({"skill": name, "kind": "skill-added",
                           "detail": "present in the tree, absent from the baseline"})
            continue
        if isnow is None:
            drifts.append({"skill": name, "kind": "skill-removed",
                           "detail": "in the baseline, absent from the tree"})
            continue
        if isnow.get("unreadable"):
            drifts.append({"skill": name, "kind": "unreadable",
                           "detail": isnow["unreadable"]})
            continue
        lost = []
        for marker, count in (was.get("markers") or {}).items():
            current = (isnow.get("markers") or {}).get(marker, 0)
            if current < count:
                lost.append(f"{marker!r} {count}->{current}")
        if lost:
            drifts.append({"skill": name, "kind": "marker-lost",
                           "detail": "; ".join(lost)})
        elif was.get("sha256") != isnow.get("sha256"):
            delta = (isnow.get("bytes", 0)) - (was.get("bytes", 0))
            drifts.append({"skill": name, "kind": "content-changed",
                           "detail": f"digest moved, {delta:+d} bytes, no guardrail marker lost"})

    marker_losses = [d for d in drifts if d["kind"] in ("marker-lost", "skill-removed")]
    return {"ok": not drifts, "blocking": bool(strict and marker_losses),
            "state": "drifted" if drifts else "intact",
            "counts": {"skills": len(now), "drifts": len(drifts),
                       "marker_losses": len(marker_losses)},
            "drifts": drifts}


def report_text(result: Dict[str, Any]) -> str:
    """One-screen summary for the CLI and the run preflight."""
    if result["state"] == "no-baseline":
        return f"skills: no integrity baseline — {result['detail']}"
    if result["state"] == "intact":
        n = result["counts"]["skills"]
        return f"skills: {n} intact, digests match the recorded baseline"
    lines = [f"skills: {result['counts']['drifts']} drifted of {result['counts']['skills']} "
             f"({result['counts']['marker_losses']} lost a guardrail marker)"]
    for d in result["drifts"]:
        flag = "!!" if d["kind"] in ("marker-lost", "skill-removed") else "  "
        lines.append(f"  {flag} {d['skill']:26} {d['kind']:16} {d['detail'][:96]}")
    if result["counts"]["marker_losses"]:
        lines.append("  a lost marker means a skill states fewer limits on who may be tested "
                     "or through which channel than when it was reviewed; read the diff")
    return "\n".join(lines)
