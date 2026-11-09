"""Finding lifecycle, chain links and the outcome log (stored in the campaign's recon.db).

Stages (each move is gated and logged):

    lead -> confirmed -> impact-proven -> reported -> accepted | duplicate | informative | n-a
      \\________\\______________\\-> killed   (validator rejected it; a reason is required)

    lead -> confirmed       needs a replay artifact AND a negative-control artifact (different
                            content): the same check must succeed on the target and fail on the
                            control (other account / patched path / unauthenticated).
    confirmed -> impact-proven  needs an impact artifact (what an attacker actually gets).
    -> reported             from confirmed or impact-proven.
    reported -> outcome     the platform's triage result.

Artifacts are copied into .recon/evidence/ by SHA-256; this module records them, it does not
judge their content. That judgement is the validator's job (see recon/prompts/validator.md).

Every transition writes one row to finding_events with the bug class, severity and tech
stack. That table is the raw history a later "what worked for me" ranking is built from.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from .store import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  bug_class TEXT NOT NULL,
  asset_id INTEGER REFERENCES assets(id),
  url TEXT,
  host TEXT,
  stage TEXT NOT NULL DEFAULT 'lead',
  severity TEXT,
  tech TEXT NOT NULL DEFAULT '[]',
  source TEXT NOT NULL DEFAULT 'manual',
  priority INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT '{}',
  dedup_key TEXT UNIQUE,
  created TEXT,
  updated TEXT);
CREATE TABLE IF NOT EXISTS finding_events(
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES findings(id),
  from_stage TEXT,
  to_stage TEXT NOT NULL,
  bug_class TEXT,
  severity TEXT,
  tech TEXT,
  note TEXT,
  evidence TEXT NOT NULL DEFAULT '{}',
  ts TEXT);
CREATE TABLE IF NOT EXISTS finding_links(
  src INTEGER NOT NULL REFERENCES findings(id),
  relation TEXT NOT NULL,
  dst INTEGER NOT NULL REFERENCES findings(id),
  note TEXT,
  created TEXT,
  PRIMARY KEY(src, relation, dst));
"""

STAGES = ("lead", "confirmed", "impact-proven", "reported",
          "accepted", "duplicate", "informative", "n-a", "killed")
OUTCOMES = ("accepted", "duplicate", "informative", "n-a")
TERMINAL = set(OUTCOMES) | {"killed"}
DEAD = {"killed", "duplicate", "informative", "n-a"}
TRANSITIONS = {
    "lead": {"confirmed", "killed"},
    "confirmed": {"impact-proven", "reported", "killed"},
    "impact-proven": {"reported", "killed"},
    "reported": set(OUTCOMES),
}
SEVERITIES = ("none", "low", "medium", "high", "critical")
RELATIONS = ("yields-token", "yields-id", "yields-access", "authenticates-to",
             "escalates-via", "pivots-to", "enables", "same-root-cause")
COVERAGE_FOR_STAGE = {"lead": "queued", "confirmed": "confirmed", "killed": "refuted"}

# Unlinked findings on the same host whose classes commonly chain into a higher severity.
CHAIN_HINTS: Tuple[Tuple[str, str, str], ...] = (
    ("open-redirect", "oauth", "redirect_uri allowlist bypass -> code/token theft -> ATO"),
    ("open-redirect", "ssrf", "redirect through an allowed host to bypass the SSRF allowlist"),
    ("xss", "ato", "XSS -> read token / change email from the victim session -> ATO"),
    ("xss", "csrf", "XSS defeats CSRF tokens -> any state change as the victim"),
    ("csrf", "ato", "CSRF on email/password/MFA change -> ATO"),
    ("idor-bola", "ato", "IDOR on email/phone/reset fields -> ATO"),
    ("idor-bola", "access-control", "read another tenant's object, then act on it as that role"),
    ("mass-assignment", "access-control", "set role/tenant fields -> privilege escalation"),
    ("file-upload", "xss", "uploaded SVG/HTML served inline -> stored XSS"),
    ("ssrf", "cloud-metadata", "SSRF -> instance metadata credentials -> cloud access"),
    ("info-disclosure", "access-control", "leaked key/token/ID -> authenticated access"),
    ("known-cve", "access-control", "pre-auth CVE on an internal/admin surface"),
)


class StageError(ValueError):
    pass


def ensure_schema(store) -> None:
    store.db.executescript(SCHEMA)
    store.db.commit()


def _row(r) -> Dict[str, Any]:
    d = dict(r)
    d["tech"] = json.loads(d.get("tech") or "[]")
    d["detail"] = json.loads(d.get("detail") or "{}")
    return d


def _clean_severity(sev: Optional[str]) -> Optional[str]:
    if sev is None:
        return None
    s = sev.strip().lower()
    if s not in SEVERITIES:
        raise StageError(f"severity must be one of {SEVERITIES}")
    return s


class Findings:
    def __init__(self, ctx):
        self.ctx = ctx
        self.store = ctx.store
        self.db = ctx.store.db
        ensure_schema(ctx.store)
        self.evidence_dir = ctx.campaign.state_dir / "evidence"

    # ---------------- create / read ----------------
    def add(self, title: str, bug_class: str, *, asset_id: Optional[int] = None,
            url: Optional[str] = None, severity: Optional[str] = None,
            tech: Iterable[str] = (), source: str = "manual", priority: int = 0,
            detail: Optional[Dict[str, Any]] = None, dedup_key: Optional[str] = None,
            note: Optional[str] = None) -> Tuple[int, bool]:
        """Create a lead. Returns (id, created). An existing dedup_key returns the old row."""
        if not title.strip() or not bug_class.strip():
            raise StageError("title and bug class are required")
        if dedup_key:
            r = self.db.execute("SELECT id FROM findings WHERE dedup_key=?", (dedup_key,)).fetchone()
            if r:
                return r["id"], False
        host = None
        if asset_id is not None:
            a = self.store.get_asset(asset_id)
            url = url or a["value"]
            host = a.get("host")
        if url:
            if not self.ctx.campaign.scope.is_in(url):
                raise StageError(f"{url} is out of scope; findings are only tracked in scope")
            host = host or (urlsplit(url).hostname or "").lower()
        sev = _clean_severity(severity)
        ts = now()
        cur = self.db.execute(
            "INSERT INTO findings(title, bug_class, asset_id, url, host, stage, severity, tech,"
            " source, priority, detail, dedup_key, created, updated)"
            " VALUES(?,?,?,?,?,'lead',?,?,?,?,?,?,?,?)",
            (title.strip(), bug_class.strip().lower(), asset_id, url, host, sev,
             json.dumps(sorted(set(tech))), source, int(priority), json.dumps(detail or {}),
             dedup_key, ts, ts))
        fid = cur.lastrowid
        self._event(fid, None, "lead", note=note)
        self._sync_coverage(fid, "lead")
        self.db.commit()
        return fid, True

    def get(self, fid: int) -> Dict[str, Any]:
        r = self.db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if not r:
            raise KeyError(f"no finding {fid}")
        return _row(r)

    def all(self, stage: Optional[str] = None) -> List[Dict[str, Any]]:
        q, args = "SELECT * FROM findings", ()
        if stage:
            q, args = q + " WHERE stage=?", (stage,)
        return [_row(r) for r in self.db.execute(q + " ORDER BY priority DESC, id", args)]

    def events(self, fid: Optional[int] = None) -> List[Dict[str, Any]]:
        q, args = "SELECT * FROM finding_events", ()
        if fid is not None:
            q, args = q + " WHERE finding_id=?", (fid,)
        out = []
        for r in self.db.execute(q + " ORDER BY id", args):
            d = dict(r)
            d["tech"] = json.loads(d.get("tech") or "[]")
            d["evidence"] = json.loads(d.get("evidence") or "{}")
            out.append(d)
        return out

    # ---------------- transitions ----------------
    def move(self, fid: int, to: str, *, note: Optional[str] = None,
             replay: Optional[Path] = None, control: Optional[Path] = None,
             impact: Optional[Path] = None, report: Optional[Path] = None,
             severity: Optional[str] = None) -> Dict[str, Any]:
        f = self.get(fid)
        cur = f["stage"]
        if to not in STAGES:
            raise StageError(f"stage must be one of {STAGES}")
        if to not in TRANSITIONS.get(cur, set()):
            allowed = sorted(TRANSITIONS.get(cur, set())) or "none (terminal)"
            raise StageError(f"finding {fid}: {cur} -> {to} not allowed; next: {allowed}")
        evidence: Dict[str, Any] = {}
        if to == "confirmed":
            if not replay or not control:
                raise StageError("confirmed needs --replay (succeeds on target) and --control "
                                 "(same check failing on another account/patched path/no auth)")
            evidence["replay"] = self._keep(replay)
            evidence["control"] = self._keep(control)
            if evidence["replay"]["sha256"] == evidence["control"]["sha256"]:
                raise StageError("replay and control are identical; a negative control must "
                                 "show the check failing")
        if to == "impact-proven":
            if not impact:
                raise StageError("impact-proven needs --impact (what the attacker actually gets)")
            evidence["impact"] = self._keep(impact)
        if to == "killed" and not (note and note.strip()):
            raise StageError("killed needs --note with the reason (it trains future ranking)")
        if report:
            evidence["report"] = self._keep(report)
        sev = _clean_severity(severity)
        self.db.execute("UPDATE findings SET stage=?, severity=COALESCE(?, severity), updated=?"
                        " WHERE id=?", (to, sev, now(), fid))
        self._event(fid, cur, to, note=note, evidence=evidence)
        self._sync_coverage(fid, to)
        self.db.commit()
        return self.get(fid)

    def link(self, src: int, relation: str, dst: int, note: Optional[str] = None) -> bool:
        if relation not in RELATIONS:
            raise StageError(f"relation must be one of {RELATIONS}")
        if src == dst:
            raise StageError("a finding cannot link to itself")
        self.get(src), self.get(dst)
        cur = self.db.execute("INSERT OR IGNORE INTO finding_links(src, relation, dst, note,"
                              " created) VALUES(?,?,?,?,?)", (src, relation, dst, note, now()))
        self.db.commit()
        return cur.rowcount == 1

    def links(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.execute("SELECT * FROM finding_links ORDER BY src, dst")]

    # ---------------- chains ----------------
    def chains(self, max_len: int = 5) -> List[List[Dict[str, Any]]]:
        """Maximal linked paths of >= 2 live findings: [{finding, relation-to-next}, ...]."""
        live = {f["id"]: f for f in self.all() if f["stage"] not in DEAD}
        out_edges: Dict[int, List[Tuple[str, int]]] = defaultdict(list)
        has_in = set()
        for l in self.links():
            if l["src"] in live and l["dst"] in live:
                out_edges[l["src"]].append((l["relation"], l["dst"]))
                has_in.add(l["dst"])
        paths: List[List[Dict[str, Any]]] = []

        def walk(node: int, path: List[Dict[str, Any]], seen: set) -> None:
            nxt = [(r, d) for r, d in out_edges.get(node, []) if d not in seen]
            if not nxt or len(path) >= max_len:
                if len(path) >= 2:
                    paths.append(path)
                return
            for rel, d in nxt:
                walk(d, path[:-1] + [dict(path[-1], relation=rel), {"finding": live[d]}],
                     seen | {d})

        starts = [n for n in out_edges if n not in has_in] or list(out_edges)
        for s in starts:
            walk(s, [{"finding": live[s]}], {s})
        return paths

    def chain_hints(self) -> List[Dict[str, Any]]:
        """Unlinked live findings on one host whose classes commonly chain."""
        live = [f for f in self.all() if f["stage"] not in DEAD
                and f["detail"].get("kind") != "client-lib"]  # outdated JS lib is not a pivot
        linked = {(l["src"], l["dst"]) for l in self.links()}
        linked |= {(b, a) for a, b in linked}
        by_host: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in live:
            by_host[f["host"] or ""].append(f)
        hints = []
        for host, fs in by_host.items():
            for a_cls, b_cls, why in CHAIN_HINTS:
                for a in (f for f in fs if f["bug_class"] == a_cls):
                    for b in (f for f in fs if f["bug_class"] == b_cls):
                        if a["id"] != b["id"] and (a["id"], b["id"]) not in linked:
                            hints.append({"host": host, "a": a, "b": b, "why": why})
        return hints

    # ---------------- outcome log (feeds a later "what worked" ranking) ----------------
    def outcome_table(self) -> List[Dict[str, Any]]:
        """Final stage per finding, grouped by bug class x tech tag."""
        rows: Counter = Counter()
        for f in self.all():
            if f["stage"] not in TERMINAL and f["stage"] != "reported":
                continue
            for t in (f["tech"] or ["(unknown)"]):
                rows[(f["bug_class"], t, f["stage"])] += 1
        return [{"bug_class": c, "tech": t, "outcome": o, "n": n}
                for (c, t, o), n in sorted(rows.items())]

    # ---------------- internals ----------------
    def _keep(self, path: Path) -> Dict[str, Any]:
        p = Path(path)
        if not p.is_file() or p.stat().st_size == 0:
            raise StageError(f"evidence file {p} missing or empty")
        data = p.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        dst = self.evidence_dir / (sha + (p.suffix if len(p.suffix) <= 8 else ""))
        if not dst.exists():
            shutil.copyfile(p, dst)
        return {"sha256": sha, "name": p.name, "bytes": len(data),
                "stored": str(dst.relative_to(self.ctx.campaign.root))}

    def _event(self, fid: int, frm: Optional[str], to: str, note: Optional[str] = None,
               evidence: Optional[Dict[str, Any]] = None) -> None:
        f = self.get(fid)
        self.db.execute(
            "INSERT INTO finding_events(finding_id, from_stage, to_stage, bug_class, severity,"
            " tech, note, evidence, ts) VALUES(?,?,?,?,?,?,?,?,?)",
            (fid, frm, to, f["bug_class"], f["severity"], json.dumps(f["tech"]), note,
             json.dumps(evidence or {}), now()))

    def _sync_coverage(self, fid: int, stage: str) -> None:
        f = self.get(fid)
        status = COVERAGE_FOR_STAGE.get(stage)
        if f["asset_id"] is None or not status:
            return
        cur = self.db.execute("SELECT status FROM coverage WHERE asset_id=? AND bug_class=?",
                              (f["asset_id"], f["bug_class"])).fetchone()
        if stage == "lead" and cur and cur["status"] not in ("untested",):
            return  # never downgrade a worked row back to queued
        self.store.set_coverage(f["asset_id"], f["bug_class"], status, f"finding #{fid}")


# ---------------- report ----------------
def _cell(v: Any) -> str:
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")[:160]


def _table(head: List[str], rows: List[List[Any]]) -> str:
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(_cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def write_findings(ctx, ts: Optional[str] = None) -> Path:
    fx = Findings(ctx)
    camp = ctx.campaign
    allf = fx.all()
    by_stage = Counter(f["stage"] for f in allf)
    md = [f"---\ntags: [campaign, findings]\nprogram: {camp.program}\ngenerated: {ts or now()}\n---\n",
          f"# Findings: {camp.program}\n",
          "Stages: lead → confirmed (replay + negative control) → impact-proven → reported → "
          "accepted / duplicate / informative / n-a, or killed. Move with "
          "`python3 -m recon finding move <campaign> <id> <stage> ...`.\n",
          _table(["stage", "count"], [[s, by_stage.get(s, 0)] for s in STAGES if by_stage.get(s)]),
          "\n## Chains (linked)\n"]
    chains = fx.chains()
    if chains:
        for c in chains:
            parts = []
            for step in c:
                f = step["finding"]
                parts.append(f"#{f['id']} {f['bug_class']} [{f['stage']}]")
                if step.get("relation"):
                    parts.append(f"--{step['relation']}->")
            md.append("- " + " ".join(parts) + "\n")
    else:
        md.append("_none: link findings with `finding link <campaign> <src> <relation> <dst>`_\n")
    hints = fx.chain_hints()
    md.append("\n## Chain hints (same host, not yet linked)\n")
    md.append(_table(["host", "a", "b", "why it can chain"],
                     [[h["host"], f"#{h['a']['id']} {h['a']['bug_class']}",
                       f"#{h['b']['id']} {h['b']['bug_class']}", h["why"]] for h in hints[:60]]))
    for stage in ("impact-proven", "confirmed", "reported", "lead"):
        rows = [f for f in allf if f["stage"] == stage]
        md.append(f"\n## {stage} ({len(rows)})\n")
        md.append(_table(["id", "prio", "class", "sev", "title", "where", "source", "tech"],
                         [[f["id"], f["priority"], f["bug_class"], f["severity"], f["title"],
                           f["url"], f["source"], ", ".join(f["tech"][:4])] for f in rows[:200]]))
    md.append("\n## Outcome log (raw history for a later what-worked ranking)\n")
    md.append(_table(["class", "tech", "outcome", "n"],
                     [[r["bug_class"], r["tech"], r["outcome"], r["n"]] for r in fx.outcome_table()]))
    p = camp.root / "findings.md"
    p.write_text("\n".join(md), encoding="utf-8")
    return p
