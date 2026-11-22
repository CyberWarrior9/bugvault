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
import re
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
  poe_level INTEGER NOT NULL DEFAULT 0,
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

#: Proof-of-exploitation level (ARTEX `server/orchestration.go:457`), enforced here
#: rather than left as free text:
#:   0 nothing yet · 1 error, timing or response variation · 2 structural manipulation
#:   3 data actually extracted or an action actually performed
#:   4 critical impact demonstrated — and for a data-exposure finding, "critical" is not
#:     a word a worker may choose: it has to fall out of the `data_impact` measurement.
POE_LEVELS = (0, 1, 2, 3, 4)

#: The most severity a stage and proof level can carry on their own. The effective
#: ceiling is this *and* the data ceiling from `dataimpact.ceiling`, whichever is lower.
#: `lead` is handled separately (always "none"), so only the two provable stages appear.
STAGE_CEILING = {
    ("confirmed", 0): "medium", ("confirmed", 1): "medium", ("confirmed", 2): "medium",
    ("confirmed", 3): "medium", ("confirmed", 4): "medium",
    ("impact-proven", 3): "high", ("impact-proven", 4): "critical",
}

#: Classes whose impact *is* data exposure, so `impact-proven` has to answer "how much
#: of what" with a `dataimpact` measurement. Reaching the surface is not the impact.
DATA_EXPOSURE_CLASSES = frozenset({
    "info-disclosure", "cloud-metadata", "js-bundle", "idor-bola", "access-control",
    "mass-assignment", "sqli", "ssrf", "xxe", "file-read", "graphql", "ssti",
    "command-injection", "deserialization", "cache", "subdomain-takeover",
})

#: What an `impact-proven` finding actually demonstrates. A class in
#: `DATA_EXPOSURE_CLASSES` defaults to `data-exposure` and then owes a `dataimpact`
#: measurement; declaring another kind says in the record that this finding is about an
#: action rather than data, which the validator can see and dispute. An access-control
#: finding that *renames* another tenant's object is a `state-change`; one that *reads*
#: it is `data-exposure`, and the same class covers both.
IMPACT_KINDS = ("data-exposure", "state-change", "account-takeover", "code-execution",
                "denial")

#: A measurement may be declined only by saying so explicitly, with a reason.
NOT_MEASURABLE = "not measurable:"
_MEASURED = re.compile(r"\b\d+\s*(?:/|of|out of)\s*\d+\b", re.I)
RELATIONS = ("yields-token", "yields-id", "yields-access", "authenticates-to",
             "escalates-via", "pivots-to", "enables", "same-root-cause",
             "spawns", "derived-from", "proves")
COVERAGE_FOR_STAGE = {"lead": "queued", "confirmed": "confirmed", "killed": "refuted"}

# Unlinked findings on the same host whose classes commonly chain into a higher severity.
CHAIN_HINTS: Tuple[Tuple[str, str, str], ...] = (
    ("security-misconfiguration", "ato", "uneven auth policy, token reuse or live session "
     "after logout -> owned-account takeover; posture alone is not a finding"),
    ("security-misconfiguration", "csrf", "missing framing restriction on a sensitive "
     "owned-account action -> browser-initiated clickjacking/CSRF proof"),
    ("security-misconfiguration", "info-disclosure", "NTLM or ASP.NET configuration "
     "exposure -> independently verified sensitive information, not a banner alone"),
    ("open-redirect", "oauth", "redirect_uri allowlist bypass -> code/token theft -> ATO"),
    ("open-redirect", "ssrf", "redirect through an allowed host to bypass the SSRF allowlist"),
    ("xss", "ato", "XSS -> read token / change email from the victim session -> ATO"),
    ("xss", "csrf", "XSS defeats CSRF tokens -> any state change as the victim"),
    ("xss", "access-control", "XSS on an admin surface -> act on admin-only objects"),
    ("html-injection", "ato", "attacker structure in rendered content -> token/session capture -> ATO"),
    ("sqli", "ato", "SQLi login bypass -> authenticated session of a supplied test account"),
    ("ssti", "access-control", "template evaluation -> code-exec-equivalent proof -> scope-capped action"),
    ("csrf", "ato", "CSRF on email/password/MFA change -> ATO"),
    ("csrf", "ssrf", "CSRF on webhook/integration settings -> server-side fetch to a chosen URL"),
    ("subdomain-takeover", "csrf", "control of a same-site sibling origin -> SameSite bypass -> CSRF"),
    ("subdomain-takeover", "xss", "conditional trusted script origin; prove reachable script load and execution, not CSP inclusion alone"),
    ("subdomain-takeover", "oauth", "conditional redirect trust; prove accepted redirect, code delivery and PKCE/client constraints"),
    ("subdomain-takeover", "access-control", "conditional CORS trust; prove credentialed browser read on an owned account"),
    ("subdomain-takeover", "info-disclosure", "conditional mail dependency; only owned test messages and explicit mail-testing permission"),
    ("idor-bola", "ato", "IDOR on email/phone/reset fields -> ATO"),
    ("idor-bola", "access-control", "read another tenant's object, then act on it as that role"),
    ("mass-assignment", "access-control", "set role/tenant fields -> privilege escalation"),
    ("file-upload", "xss", "uploaded SVG/HTML served inline -> stored XSS"),
    ("ssrf", "cloud-metadata", "SSRF -> instance metadata credentials -> cloud access"),
    ("info-disclosure", "access-control", "leaked key/token/ID -> authenticated access"),
    ("known-cve", "access-control", "pre-auth CVE on an internal/admin surface"),

    # ---- backfill 2026-11-22: twelve routed classes had no edge in either direction,
    # so `chain status` could not propose a next step for them. Each row below names the
    # observation that licenses the edge, not merely that two classes are related.
    ("http-smuggling", "cache", "a smuggled request's response is stored under a popular "
     "key -> every later viewer is served it; needs a second client you control, not a "
     "shared production key"),
    ("http-smuggling", "access-control", "smuggle a prefix past the front-end ACL -> the "
     "back-end treats it as internally routed; prove the route was externally refused first"),
    ("http-smuggling", "idor-bola", "a smuggled request pairs with the next connection's "
     "credentials -> that principal's object in your response queue; only between owned clients"),
    ("cache", "xss", "a poisoned cacheable asset or HTML serves attacker script to a second "
     "viewer -> stored-XSS-equivalent; browser execution must be shown, not reflected bytes"),
    ("cache", "ato", "cache deception stores an authenticated representation under an "
     "unauthenticated key -> a second viewer reads the session owner's data"),
    ("xxe", "ssrf", "an external entity resolves an attacker-chosen URL -> server-side fetch; "
     "a fetched DTD is reach, not file read"),
    ("xxe", "info-disclosure", "entity expansion returns local file content in-band or in an "
     "error -> file read without any egress"),
    ("deserialization", "command-injection", "a gadget chain reaches a process or shell sink "
     "-> execution; a decode error does not close the sink, __destruct fires on failure too"),
    ("deserialization", "access-control", "a forged object sets role, tenant or identity "
     "fields the API never exposes -> privileged state without an object swap"),
    ("command-injection", "cloud-metadata", "execution on an instance -> metadata credentials; "
     "marker output alone is execution, the credential read is the separate impact fact"),
    ("graphql", "idor-bola", "introspection or suggestion leakage names node ids and object "
     "references that the REST surface never exposed -> substitution targets"),
    ("graphql", "access-control", "field-level policy differs from node-level policy -> read a "
     "field the operation should have denied"),
    ("js-bundle", "info-disclosure", "a bundle or source map carries a key, internal hostname "
     "or privileged operation -> verified disclosure, never the static reference alone"),
    ("js-bundle", "idor-bola", "a bundle names object-scoped endpoints absent from the live "
     "surface -> identifiers to substitute"),
    ("race-conditions", "business-logic", "a schedule-dependent write violates a declared owned "
     "invariant -> the logic consequence is the finding, the race is the mechanism"),
    ("business-logic", "ato", "an invariant violation yields control of another owned account's "
     "state; terminal impact, not an unexplained value"),
    ("mfa-bypass", "ato", "a post-MFA server session obtained without the second factor -> "
     "takeover of the owned account that factor protected"),
    ("saml", "ato", "an accepted assertion for a second owned test identity -> that account's "
     "session; a signature-check failure alone is not acceptance"),
    ("saml", "access-control", "role or group claims honoured from an attacker-influenced "
     "assertion -> privileged function"),
    ("oauth", "ato", "an exchanged code or token for a second owned account -> its session; "
     "closes the dead end where oauth was only ever a chain target"),
    ("access-control", "info-disclosure", "reached an admin or internal surface -> configuration, "
     "key or credential read; closes the dead end where access-control never chained onward"),
    ("cloud-misconfiguration", "info-disclosure", "a readable storage object or exposed metadata "
     "endpoint -> independently verified sensitive content, not a public identifier"),
    ("cloud-misconfiguration", "ato", "a recovered cloud credential or signed URL grants an owned "
     "account's data or an identity pivot; requires the operator's own approved exercise"),
)


class StageError(ValueError):
    pass


def ensure_schema(store) -> None:
    store.db.executescript(SCHEMA)
    # Campaigns created before proof levels existed keep their rows; the column is
    # added in place and defaults to 0 ("nothing proven yet"), never to a claim.
    columns = {r["name"] for r in store.db.execute("PRAGMA table_info(findings)")}
    if "poe_level" not in columns:
        store.db.execute("ALTER TABLE findings ADD COLUMN poe_level INTEGER NOT NULL DEFAULT 0")
    store.db.commit()


def severity_ceiling(stage: str, poe_level: Optional[int],
                     measurement: Optional[Dict[str, Any]] = None,
                     kind: str = "data-exposure") -> str:
    """The highest severity a finding may carry, from its proof and its data.

    Two independent caps, and the lower one wins: what the stage and proof level can
    support at all, and what the measured data is actually worth. A demonstrated
    primitive with uncharacterised data is capped at medium by the second cap even when
    the first would allow critical — which is the point of the 2026-11-22 decision.

    The data cap applies to a `data-exposure` finding always, and to any other kind that
    supplied a measurement anyway. A proven state change with no data read is rated by
    its stage and proof level, because there is no data to count.
    """
    from .dataimpact import ceiling as data_ceiling

    if stage == "lead":
        stage_cap = "none"
    elif stage in ("confirmed", "impact-proven"):
        stage_cap = STAGE_CEILING.get((stage, poe_level if poe_level is not None else 0), "medium")
    else:
        return SEVERITIES[-1]  # reported/terminal stages keep whatever triage decided
    if stage != "impact-proven":
        return stage_cap
    if kind != "data-exposure" and not measurement:
        return stage_cap
    return min(stage_cap, data_ceiling(measurement), key=SEVERITIES.index)


def _row(r) -> Dict[str, Any]:
    d = dict(r)
    d["tech"] = json.loads(d.get("tech") or "[]")
    d["detail"] = json.loads(d.get("detail") or "{}")
    return d


def _clean_poe(level: Any) -> int:
    if type(level) is not int or level not in POE_LEVELS:
        raise StageError(f"poe_level must be one of {POE_LEVELS}")
    return level


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
        else:
            raise StageError("a finding requires an in-scope URL or URL-bearing asset")
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
             severity: Optional[str] = None, poe_level: Optional[int] = None,
             measurement: Optional[str] = None, quote: Optional[str] = None,
             data_impact: Optional[Dict[str, Any]] = None,
             override: Optional[str] = None,
             impact_kind: Optional[str] = None) -> Dict[str, Any]:
        f = self.get(fid)
        cur = f["stage"]
        if to not in TERMINAL and f["url"] and not self.ctx.campaign.scope.is_in(f["url"]):
            raise StageError("finding URL is no longer in scope; re-scope before further validation")
        if to not in STAGES:
            raise StageError(f"stage must be one of {STAGES}")
        if to not in TRANSITIONS.get(cur, set()):
            allowed = sorted(TRANSITIONS.get(cur, set())) or "none (terminal)"
            raise StageError(f"finding {fid}: {cur} -> {to} not allowed; next: {allowed}")
        evidence: Dict[str, Any] = {}
        # A measurement is validated and recorded wherever it is supplied, not only on
        # the move to impact-proven: a `--data-impact` that was quietly ignored on some
        # other transition would be a silent hole in the no-raw-values rule, and would
        # also lose a measurement the author believed was recorded.
        if data_impact is not None:
            from .dataimpact import MeasurementError, summarise, validate
            try:
                evidence["data_impact"] = validate(data_impact)
            except MeasurementError as error:
                raise StageError(str(error)) from error
            evidence["data_impact_summary"] = summarise(evidence["data_impact"])
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
            evidence.update(self._impact_gate(f, Path(impact), poe_level, measurement,
                                              quote, evidence.get("data_impact"),
                                              impact_kind))
        if to == "killed" and not (note and note.strip()):
            raise StageError("killed needs --note with the reason (it trains future ranking)")
        if report:
            evidence["report"] = self._keep(report)
        sev = _clean_severity(severity)
        level = f["poe_level"] if poe_level is None else _clean_poe(poe_level)
        if sev is not None and to not in TERMINAL:
            cap = severity_ceiling(to, level, evidence.get("data_impact"),
                                   evidence.get("impact_kind", "data-exposure"))
            if SEVERITIES.index(sev) > SEVERITIES.index(cap):
                if not (override and override.strip()):
                    raise StageError(
                        f"severity {sev!r} is above the {cap!r} ceiling for stage {to!r} at "
                        f"PoE {level}"
                        + (f" with {evidence['data_impact']['tier']}-tier data "
                           f"({evidence['data_impact']['reachable']} items reachable)"
                           if evidence.get("data_impact") else
                           " with the data left uncharacterised")
                        + ". Measure more of the data, or pass --override with the reason "
                          "the ceiling is wrong here.")
                evidence["severity_override"] = {
                    "claimed": sev, "ceiling": cap, "reason": override.strip()[:500]}
        self.db.execute("UPDATE findings SET stage=?, severity=COALESCE(?, severity),"
                        " poe_level=?, updated=? WHERE id=?", (to, sev, level, now(), fid))
        self._event(fid, cur, to, note=note, evidence=evidence)
        self._sync_coverage(fid, to)
        self.db.commit()
        return self.get(fid)

    def _impact_gate(self, f: Dict[str, Any], impact: Path, poe_level: Optional[int],
                     measurement: Optional[str], quote: Optional[str],
                     data_impact: Optional[Dict[str, Any]],
                     kind: Optional[str] = None) -> Dict[str, Any]:
        """What `impact-proven` has to carry beyond an artifact (plan §5.2).

        A proof level of at least 3, a measurement with a denominator, one verbatim
        quote that is actually present in the bound artifact, and — for a class whose
        impact is data exposure — a `dataimpact` measurement saying how much of what.

        `data_impact` arrives already validated by `move`.
        """
        from .dataimpact import summarise

        level = _clean_poe(poe_level if poe_level is not None else f["poe_level"])
        if level < 3:
            raise StageError(
                f"impact-proven needs --poe-level 3 or 4, got {level}. PoE 3 is data "
                "actually extracted or an action actually performed; an error, a timing "
                "difference or a structural manipulation is PoE 1-2 and stays confirmed.")

        text = " ".join(str(measurement or "").split())
        if not text:
            raise StageError(
                "impact-proven needs --measurement: a number with a denominator, such as "
                "\"3 of 20 variants returned other-tenant rows; 17 rejected\", or "
                f"\"{NOT_MEASURABLE} <reason>\" if it genuinely cannot be counted.")
        if not text.lower().startswith(NOT_MEASURABLE) and not _MEASURED.search(text):
            raise StageError(
                f"--measurement {text!r} has no denominator. Give the numerator and the "
                f"denominator (\"4 of 50\"), and say what the defence blocked, or state "
                f"\"{NOT_MEASURABLE} <reason>\".")

        if not (quote and quote.strip()):
            raise StageError("impact-proven needs --quote: a verbatim string from the "
                             "impact artifact that shows the result")
        blob = Path(impact).read_bytes()
        needle = quote.strip().encode("utf-8", "replace")
        # Headers count, not only the body: an attacker-visible Set-Cookie or Location
        # is as much a result as a row of data (ARTEX checks the body alone).
        if needle not in blob:
            raise StageError(
                f"--quote is not present verbatim in {Path(impact).name}; the impact "
                "claim must quote the artifact it is bound to, headers included")

        if kind is not None and kind not in IMPACT_KINDS:
            raise StageError(f"impact kind must be one of {IMPACT_KINDS}")
        declared = kind or ("data-exposure" if f["bug_class"] in DATA_EXPOSURE_CLASSES
                            else "state-change")
        out: Dict[str, Any] = {"poe_level": level, "measurement": text,
                               "impact_kind": declared, "quote": quote.strip()[:500]}
        if data_impact is None:
            if declared == "data-exposure":
                raise StageError(
                    f"this {f['bug_class']} finding claims data exposure, so "
                    "impact-proven needs --data-impact: how many items are reachable, "
                    "how many you characterised, what each is (see recon/dataimpact.py "
                    "CLASSES) and what the data is about. Reaching the surface is not "
                    "the impact. If the impact is an action rather than data, say so "
                    f"with --impact-kind from {IMPACT_KINDS[1:]}.")
            return out
        if declared == "data-exposure" and level == 4 and data_impact["ceiling"] != "critical":
            raise StageError(
                f"PoE 4 needs data worth critical, but this measurement supports "
                f"{data_impact['ceiling']!r}: {summarise(data_impact)}. Either measure "
                "more of what is reachable, or record PoE 3.")
        return out

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
            dst.write_bytes(data)  # copy the exact bytes hashed, not a second read of the source
        elif hashlib.sha256(dst.read_bytes()).hexdigest() != sha:
            raise StageError("stored evidence hash mismatch; existing artifact was not overwritten")
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
        others = self.db.execute("SELECT stage FROM findings WHERE asset_id=? AND bug_class=? AND id!=?",
                                 (f["asset_id"], f["bug_class"], fid)).fetchall()
        if stage == "killed" and any(r["stage"] not in DEAD for r in others):
            return  # killing one hypothesis never refutes another live/confirmed finding
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
           "Artifact gates check file presence and distinct hashes only. Stage labels are "
           "validator/operator attestations, not machine-verified exploitability.\n",
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
    md.append("\n## Chain todolist (ready first; `recon chain status` for detail)\n")
    from .chain import ChainLedger
    todo = [c for c in ChainLedger(ctx).overview()["chains"] if c["state"] != "complete"]
    md.append(_table(["state", "chain", "proven", "next class", "action"],
                     [[c["state"], c["name"], f"{c['proven_steps']}/{c['total_steps']}",
                       (c["next"] or {}).get("class", "-"), c["action"] or "-"]
                      for c in todo[:40]]))
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
