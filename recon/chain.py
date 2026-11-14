"""Cross-class chain todolist and lineage (ARTEX todolist/graph ideas, natively).

Offline only. Reads findings and links, computes which chain steps are ready,
lead-open, failed or proven, and persists operator-defined custom chains.
"Proven" strictly means a finding of the step's class reached `confirmed` or
later — replay + negative control already required by the finding lifecycle.
Nothing here executes work, widens scope, or promotes findings; it orders the
hunt and keeps lineage edges honest.

Adapted ideas (not code) from ARTEX's shared todolist and exploration-graph
lineage, within BugVault's deterministic, evidence-gated model.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .findings import CHAIN_HINTS, DEAD, Findings
from .store import now

PROVEN_STAGES = {"confirmed", "impact-proven", "reported", "accepted"}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
CLASS_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
MAX_CUSTOM_CHAINS = 20
MAX_STEPS = 8

SCHEMA = """
CREATE TABLE IF NOT EXISTS chain_plans(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  steps TEXT NOT NULL,
  created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS realism_checks(
  chain_name TEXT NOT NULL,
  question TEXT NOT NULL,
  outcome TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  updated TEXT NOT NULL,
  PRIMARY KEY(chain_name, question));
"""

# Plan §6 realism gate: three mandatory questions on every impact/chain claim,
# answered with evidence before the chain may count as a reportable impact.
REALISM_QUESTIONS = (
    ("reachable", "can a real attacker reach it under the program's threat model "
                  "(not only from the operator's session/internal position/synthetic render)?"),
    ("preconditions", "is every assumed capability demonstrated (token availability, "
                      "victim interaction, attacker-holdable role), or is the chain conditional?"),
    ("downstream", "does a later layer still block the impact (CSP/nonce, server-side authz, "
                   "output encoding, credential policy, rate limits/WAF on the chained request)?"),
)
REALISM_OUTCOMES = ("pass", "fail", "unanswered")

# Hand-written multi-step chains; two-step chains are derived from
# findings.CHAIN_HINTS so the hint table stays the single source of truth.
STEP_CHAINS: Tuple[Tuple[str, str, Tuple[Tuple[str, str], ...]], ...] = (
    ("redirect-oauth-ato",
     "Open redirect -> OAuth code theft -> account takeover",
     (("open-redirect", "reachable redirect from an OAuth start URL"),
      ("oauth", "redirect_uri/state flaw delivers the code to the attacker"),
      ("ato", "exchange or reuse as the victim completes the takeover"))),
    ("idor-reset-ato",
     "IDOR on a reset/session object -> token capture -> account takeover",
     (("idor-bola", "read a reset/session/magic-link object of the victim account"),
      ("info-disclosure", "capture the reset token or session reference"),
      ("ato", "use the token to enter the victim account"))),
    ("ssrf-metadata-access",
     "SSRF -> instance metadata -> credential use on a test resource",
     (("ssrf", "server-side fetch proven with attribution and controls"),
      ("cloud-metadata", "reach the metadata endpoint and read credentials"),
      ("access-control", "use the credential on a supplied test resource"))),
    ("xss-admin-ato",
     "XSS on an admin surface -> admin-scope action -> account takeover",
     (("xss", "proven execution in the browser on an in-scope admin surface"),
      ("access-control", "act on an admin object only that role can reach"),
      ("ato", "session/token takeover on a supplied test account"))),
    ("htmli-token-ato",
     "HTML injection in rendered content -> leaked token -> account takeover",
     (("html-injection", "structure injection on a rendered content field"),
      ("info-disclosure", "capture a token or session reference the render exposes"),
      ("ato", "use the token to enter a supplied test account"))),
    ("sql-authbypass-admin",
     "SQLi login bypass -> admin session -> admin-scope action",
     (("sqli", "login bypass proven with the replayed true/false pair + negative control"),
      ("ato", "authenticated admin session on a supplied test account"),
      ("access-control", "admin-only action on a supplied test resource"))),
    ("sibling-csrf-ato",
     "Same-site sibling control -> CSRF on an account setting -> account takeover",
     (("subdomain-takeover", "control content on a same-site sibling origin (owned, supplied "
                             "or a confirmed takeover/XSS finding)"),
      ("csrf", "same-site browser-initiated change on a supplied test account"),
      ("ato", "account access through the changed setting on the supplied victim account"))),
    ("ssti-exec",
     "SSTI -> code-exec-equivalent proof -> scope-capped action",
     (("ssti", "template evaluation proven with harmless expressions"),
      ("access-control", "scope-capped action on a supplied test resource"))),
)


def _templates() -> List[Tuple[str, str, Tuple[Tuple[str, str], ...]]]:
    out: List[Tuple[str, str, Tuple[Tuple[str, str], ...]]] = list(STEP_CHAINS)
    for a, b, why in CHAIN_HINTS:
        out.append((f"hint-{a}-{b}", why,
                    ((a, f"prove {a} on an in-scope target"),
                     (b, f"prove {b} leveraging the previous step"))))
    return out


def load_plan(path) -> Dict[str, Any]:
    with Path(path).open("rb") as stream:
        data = stream.read(1_000_001)
    if len(data) > 1_000_000:
        raise ValueError("chain plan JSON exceeds one megabyte")
    return json.loads(data)


def _validate_steps(steps) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(steps, list) or not 2 <= len(steps) <= MAX_STEPS:
        raise ValueError(f"a chain needs 2..{MAX_STEPS} steps")
    clean = []
    for step in steps:
        if not isinstance(step, dict) or set(step) != {"class", "goal"}:
            raise ValueError('each step is exactly {"class", "goal"}')
        cls, goal = step["class"], step["goal"]
        if not isinstance(cls, str) or not CLASS_RE.fullmatch(cls):
            raise ValueError(f"step class {cls!r} must match {CLASS_RE.pattern}")
        if not isinstance(goal, str) or not 1 <= len(goal.strip()) <= 200 \
                or any(ord(c) < 32 for c in goal):
            raise ValueError("step goal must be 1..200 single-line characters")
        clean.append((cls, goal.strip()))
    if len(set(clean)) != len(clean):
        raise ValueError("steps must be unique; a repeated (class, goal) pair is a no-op")
    return tuple(clean)


class ChainLedger:
    def __init__(self, ctx):
        self.ctx = ctx
        self.fx = Findings(ctx)
        self.db = ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------------- custom chains ----------------
    def add(self, name: str, description: str, steps) -> int:
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ValueError(f"chain name must match {NAME_RE.pattern}")
        if not isinstance(description, str) or len(description) > 200 \
                or any(ord(c) < 32 for c in description):
            raise ValueError("description must be at most 200 single-line characters")
        clean = _validate_steps(steps)
        reserved = {n for n, _, _ in _templates()}
        if name in reserved:
            raise ValueError(f"{name!r} is a built-in chain name")
        if self.db.execute("SELECT 1 FROM chain_plans WHERE name=?", (name,)).fetchone():
            raise ValueError(f"custom chain {name!r} already exists")
        count = self.db.execute("SELECT count(*) FROM chain_plans").fetchone()[0]
        if count >= MAX_CUSTOM_CHAINS:
            raise ValueError(f"at most {MAX_CUSTOM_CHAINS} custom chains per campaign")
        cur = self.db.execute("INSERT INTO chain_plans(name, description, steps, created) "
                              "VALUES(?,?,?,?)",
                              (name, description.strip(), json.dumps(
                                  [{"class": c, "goal": g} for c, g in clean]), now()))
        self.db.commit()
        return cur.lastrowid

    def _custom(self) -> List[Tuple[str, str, Tuple[Tuple[str, str], ...]]]:
        rows = self.db.execute("SELECT * FROM chain_plans ORDER BY id").fetchall()
        return [(r["name"], r["description"],
                 tuple((s["class"], s["goal"]) for s in json.loads(r["steps"]))) for r in rows]

    # ---------------- realism gate (plan §6) ----------------
    def realism(self, chain_name: str, question: Optional[str] = None,
                outcome: Optional[str] = None, note: str = "") -> Dict[str, Any]:
        """Record one realism answer, or return the current three-question state."""
        if not isinstance(chain_name, str) or not NAME_RE.fullmatch(chain_name):
            raise ValueError(f"chain name must match {NAME_RE.pattern}")
        reserved = {n for n, _, _ in _templates()}
        if chain_name not in reserved and not self.db.execute(
                "SELECT 1 FROM chain_plans WHERE name=?", (chain_name,)).fetchone():
            raise ValueError(f"unknown chain {chain_name!r}")
        answers = {q: {"outcome": "unanswered", "note": "", "updated": None}
                   for q, _ in REALISM_QUESTIONS}
        for r in self.db.execute("SELECT * FROM realism_checks WHERE chain_name=?", (chain_name,)):
            answers[r["question"]] = {"outcome": r["outcome"], "note": r["note"],
                                      "updated": r["updated"]}
        if question is None and outcome is None:
            return {"chain": chain_name, "questions": answers,
                    "basis": "unanswered realism questions park a completed chain; "
                             "the impact artifact must carry the evidence for each answer"}
        if question not in answers:
            raise ValueError(f"question must be one of {[q for q, _ in REALISM_QUESTIONS]}")
        if outcome not in REALISM_OUTCOMES:
            raise ValueError(f"outcome must be one of {REALISM_OUTCOMES}")
        if not isinstance(note, str) or len(note) > 2000 or any(ord(c) < 32 for c in note):
            raise ValueError("note must be at most 2000 single-line characters")
        self.db.execute(
            "INSERT INTO realism_checks(chain_name, question, outcome, note, updated)"
            " VALUES(?,?,?,?,?) ON CONFLICT(chain_name, question) DO UPDATE SET"
            " outcome=excluded.outcome, note=excluded.note, updated=excluded.updated",
            (chain_name, question, outcome, note, now()))
        self.db.commit()
        return self.realism(chain_name)

    def _realism_block(self, chain_name: str) -> Dict[str, Any]:
        state = self.realism(chain_name)["questions"]
        failed = sorted(q for q, a in state.items() if a["outcome"] == "fail")
        unanswered = sorted(q for q, a in state.items() if a["outcome"] == "unanswered")
        return {"questions": state, "failed": failed, "unanswered": unanswered,
                "complete": not failed and not unanswered}

    # ---------------- todolist ----------------
    def overview(self) -> Dict[str, Any]:
        live = [f for f in self.fx.all() if f["stage"] not in DEAD]
        links = {(l["src"], l["dst"]) for l in self.fx.links()}
        chains = []
        for name, description, steps in _templates() + self._custom():
            resolved, prev_state, prev_ids = [], "ready", []
            for i, (cls, goal) in enumerate(steps):
                matching = [f for f in live if f["bug_class"] == cls]
                proven_ids = [f["id"] for f in matching if f["stage"] in PROVEN_STAGES]
                lead_ids = [f["id"] for f in matching if f["stage"] == "lead"]
                if proven_ids:
                    state = "proven"
                elif i == 0:
                    state = "ready"
                elif prev_state in ("failed", "blocked"):
                    state = "blocked"
                elif prev_state != "proven":
                    state = "waiting"
                elif matching:
                    state = "ready"
                else:
                    state = "ready"
                # A class whose every finding died is a dead pivot, not a fresh step.
                attempted = self.db.execute(
                    "SELECT count(*) FROM findings WHERE bug_class=?", (cls,)).fetchone()[0]
                if not matching and attempted and prev_state in ("proven", "ready"):
                    state = "failed" if i == 0 or prev_state == "proven" else state
                linked_from_prev = bool(i and any((a, b) in links
                                                   for a in prev_ids for b in proven_ids))
                resolved.append({"index": i, "class": cls, "goal": goal, "state": state,
                                 "proven_by": proven_ids, "lead_open": lead_ids,
                                 "attempted_dead": bool(attempted and not matching),
                                 "linked_from_prev": linked_from_prev})
                prev_state, prev_ids = state, proven_ids or prev_ids
            frontier = next((s for s in resolved if s["state"] != "proven"), None)
            if frontier is None:
                chain_state, action = "complete", None
            elif frontier["state"] in ("ready",) and frontier["lead_open"]:
                chain_state, action = "ready", f"confirm open lead(s) {frontier['lead_open']} " \
                                              f"for '{frontier['class']}' (replay + negative control)"
            elif frontier["state"] == "ready":
                chain_state, action = "ready", f"hunt '{frontier['class']}': {frontier['goal']}"
            elif frontier["state"] == "failed":
                chain_state, action = "parked", f"pivot class '{frontier['class']}' has only dead " \
                                               f"findings; park or open a new lead"
            else:
                chain_state, action = "parked", f"step {frontier['index'] + 1} blocked by a dead " \
                                                f"predecessor; park the chain"
            # Realism gate (plan §6): a chain whose terminal steps are all proven is an
            # impact claim only when the three questions are answered and passing.
            realism = self._realism_block(name)
            if chain_state == "complete" and not realism["complete"]:
                named = ", ".join(realism["failed"] + realism["unanswered"])
                chain_state, action = "parked", \
                    f"all steps proven, but the realism gate is not satisfied ({named}); " \
                    "record evidence-backed answers with `recon chain realism` before impact"
            chains.append({"name": name, "description": description, "state": chain_state,
                           "steps": resolved, "realism": realism,
                           "proven_steps": sum(s["state"] == "proven" for s in resolved),
                           "total_steps": len(resolved), "next": frontier, "action": action})
        order = {"ready": 0, "parked": 1, "complete": 2}
        chains.sort(key=lambda c: (order[c["state"]], -c["proven_steps"], c["name"]))
        return {"schema_version": 1, "chains": chains,
                "basis": "offline view over findings; proven = confirmed or later "
                         "(replay + negative control already enforced by the lifecycle)",
                "lineage": "link proven neighbours with finding link; spawns/derived-from/proves "
                           "are lineage relations; unlinked steps are flagged",
                "executed": False, "finding_promoted": False}
