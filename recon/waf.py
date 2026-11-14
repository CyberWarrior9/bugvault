"""Per-host WAF/filter profile: what a block looks like, and which elements pass.

Offline. The operator runs the probes manually in the dedicated browser through
Burp and records what came back; this module classifies the block signature and
keeps the element table (allowed/blocked per location and content type) that the
hunt-xss / hunt-sqli probe ladders and the payload context packets consume. It
generates probe *elements* to try, never evasion payloads - surviving/blocked
element knowledge feeds context-fit design, which stays a reasoning step.

Classification kinds:
  status        - blocked response status vs passing baseline (the 403 shape)
  template      - a different error/challenge page template (WAF keyword hit)
  header        - same-ish body but distinct added headers (edge signature)
  reset         - connection reset / dropped (no usable response)
  silent-strip  - probe response otherwise equals the baseline but the element
                  is gone (input strip-and-rebuild, NOT an application error:
                  an app error would differ in template shape)
  allowed       - element passed through unchanged
  modified      - body changed without a block signature (encoding/rewriting)
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .fields import mint_marker
from .store import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS waf_profiles(
  host TEXT PRIMARY KEY,
  signature TEXT NOT NULL,
  elements TEXT NOT NULL DEFAULT '[]',
  updated TEXT NOT NULL);
"""

OUTCOMES = ("allowed", "stripped", "blocked", "modified", "reset")
LOCATIONS = ("query", "json", "form", "multipart", "header", "path")
BLOCK_MARKERS = ("captcha", "challenge", "attention required", "access denied", "request blocked",
                 "request rejected", "blocked", "forbidden by", "cloudflare", "akamai",
                 "imperva", "incapsula", "sucuri", "mod_security", "modsecurity",
                 "web application firewall", "waf", "barrier", "protection")
HEADER_HINTS = ("cf-ray", "cf-cache-status", "server", "x-sucuri-id", "x-iinfo", "x-cdn",
                "x-akamai", "x-waf", "x-protected-by", "x-served-by")

# (kind, element): harmless-to-suspicious, one at a time, then pairs with the
# structural characters most contexts need. Bounded so a host profile is cheap.
SINGLES: Tuple[Tuple[str, str], ...] = (
    ("char", "<"), ("char", ">"), ("char", '"'), ("char", "'"), ("char", "`"),
    ("char", "="), ("char", "("), ("char", ")"), ("char", "/"), ("char", ";"),
    ("char", "%"), ("char", "&"), ("char", "+"), ("char", "."),
    ("comment", "--"), ("comment", "#"), ("comment", "/*"), ("comment", "*/"),
    ("tag", "<b>"), ("tag", "<script>"), ("tag", "<img>"), ("tag", "<svg>"),
    ("tag", "<iframe>"), ("tag", "<form>"), ("tag", "<a href=x>"),
    ("event", "onerror"), ("event", "onload"), ("event", "onfocus"), ("event", "onclick"),
    ("event", "javascript:"), ("event", "alert"),
    ("keyword", "UNION"), ("keyword", "SELECT"), ("keyword", "OR 1=1"), ("keyword", "AND"),
    ("keyword", "SLEEP"), ("keyword", "information_schema"),
)
PAIR_WITH = ("<", "'")
MAX_ELEMENTS_PER_HOST = 400


def _norm_digits(text: str) -> str:
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "U",
                  text, flags=re.I)
    text = re.sub(r"\b[0-9a-f]{16,}\b", "H", text, flags=re.I)
    text = re.sub(r"\d+", "N", text)
    return re.sub(r"\s+", " ", text)


def template_sha(body: bytes) -> str:
    return hashlib.sha256(_norm_digits(body.decode("utf-8", "replace")).encode()).hexdigest()


def classify(baseline_status: Optional[int], baseline_body: bytes,
             probe_status: Optional[int], probe_body: bytes, element: str,
             marker: str, reset: bool = False) -> Dict[str, Any]:
    """Deterministic block-signature classification for one probe response.

    Order: reset -> blocked status -> challenge template -> pass-through
    (element or marker echoed) -> silent-strip (baseline-equal template, element
    absent) -> modified. Pass-through does not require template equality: a
    reflected probe legitimately rewrites the page around the element.
    """
    if reset or probe_status is None and not probe_body:
        return {"kind": "reset", "status": probe_status, "template_sha": None,
                "markers_hit": [], "added_headers": [], "notes":
                "connection reset or no usable response (record explicitly with --reset)"}
    probe_text = probe_body.decode("utf-8", "replace")
    baseline_text = baseline_body.decode("utf-8", "replace")
    low = probe_text.lower()
    hits = [m for m in BLOCK_MARKERS if m in low]
    p_sha, b_sha = template_sha(probe_body), template_sha(baseline_body)
    if probe_status is not None and baseline_status is not None and probe_status >= 400 \
            and baseline_status < 400 and not hits:
        return {"kind": "status", "status": probe_status, "template_sha": p_sha,
                "markers_hit": hits, "added_headers": [], "notes":
                f"blocked response status {probe_status} vs baseline {baseline_status}"}
    if hits and p_sha != b_sha:
        return {"kind": "template", "status": probe_status, "template_sha": p_sha,
                "markers_hit": hits, "added_headers": [], "notes":
                "distinct error/challenge page template; WAF keyword hit "
                + ", ".join(hits[:5])}
    if element in probe_text or marker in probe_text:
        return {"kind": "allowed", "status": probe_status, "template_sha": p_sha,
                "markers_hit": [], "added_headers": [], "notes":
                "probe element (or marker) passed through into the response"}
    if p_sha == b_sha:
        return {"kind": "stripped", "status": probe_status, "template_sha": p_sha,
                "markers_hit": [], "added_headers": [], "notes":
                "response otherwise equals the baseline but the element is absent "
                "(silent strip; distinguish from an app error by the equal template)"}
    return {"kind": "modified", "status": probe_status, "template_sha": p_sha,
            "markers_hit": hits, "added_headers": [], "notes":
            "body differs, element absent, no block signature (encoding/rewriting); "
            "compare the marker's new representation"}


def classify_with_headers(probe_headers: Dict[str, str], baseline_headers: Dict[str, str],
                          signature: Dict[str, Any]) -> Dict[str, Any]:
    """Promote an allowed/modified result to a header-kind signature when the edge
    adds distinctive headers while the body stays comparable."""
    added = sorted(k.lower() for k in probe_headers
                   if k.lower() not in {b.lower() for b in baseline_headers}
                   and any(h in k.lower() for h in HEADER_HINTS))
    if added and signature["kind"] in ("allowed", "modified"):
        signature = dict(signature)
        signature.update({"kind": "header", "added_headers": added,
                          "notes": signature["notes"] + f"; added edge headers {added}"})
    return signature


class WAFProfiles:
    def __init__(self, ctx):
        self.ctx = ctx
        self.db = ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()

    def observe(self, host, baseline_status, baseline_body, probe_status, probe_body,
                element, marker, reset=False,
                baseline_headers=None, probe_headers=None) -> Dict[str, Any]:
        if not isinstance(host, str) or not re.fullmatch(r"[a-z0-9._*-]{1,253}", host.lower()):
            raise ValueError("host must be a host label (the profile is per host)")
        host = host.lower()
        signature = classify(baseline_status, baseline_body, probe_status, probe_body,
                             element, marker, reset=reset)
        if not reset:
            signature = classify_with_headers(probe_headers or {}, baseline_headers or {},
                                              signature)
        # Block-signature kinds map onto element outcomes: a blocked response shape
        # (status/template/header) means the element did not pass through.
        outcome = {"status": "blocked", "template": "blocked", "header": "blocked",
                   "reset": "reset"}.get(signature["kind"], signature["kind"])
        self._upsert(host, signature)
        self.record(host, element, kind="char", outcome=outcome, marker=marker,
                    note=signature["notes"])
        return {"host": host, "element": element, "signature": signature,
                "basis": "operator-supplied captures; classification is heuristic, "
                         "not a vendor identification"}

    def _upsert(self, host, signature) -> None:
        self.db.execute(
            "INSERT INTO waf_profiles(host, signature, elements, updated) VALUES(?,?, '[]', ?)"
            " ON CONFLICT(host) DO UPDATE SET signature=excluded.signature,"
            " updated=excluded.updated", (host, json.dumps(signature, sort_keys=True), now()))
        self.db.commit()

    def plan(self, host) -> Dict[str, Any]:
        if not isinstance(host, str) or not host:
            raise ValueError("host is required")
        recorded = self._elements(host)
        done = {(e["element"], e["paired_with"] or "") for e in recorded}
        probes, n = [], 0
        for element in SINGLES:
            if (element[1], "") in done:
                continue
            probes.append({"marker": mint_marker(), "kind": element[0],
                           "element": element[1], "paired_with": "", "step": "single"})
            n += 1
        for element in SINGLES:
            if element[0] in ("char", "comment"):
                continue
            for partner in PAIR_WITH:
                if (element[1], partner) in done:
                    continue
                probes.append({"marker": mint_marker(), "kind": element[0],
                               "element": element[1] + partner, "paired_with": partner,
                               "step": "pair"})
                n += 1
        probes = probes[:60]
        return {"host": host, "probes": probes, "how": "one probe at a time in the dedicated "
                "browser through Burp, per location and content type; submit the probe as the "
                "field value with the marker appended so the response can be classified; "
                "record each outcome with `recon waf record`",
                "locations": list(LOCATIONS),
                "elements_recorded": len(recorded),
                "basis": "probe sequence: single elements first, then pairs with structural "
                         "characters; markers are unique per probe for attribution",
                "executed": False}

    def _elements(self, host) -> List[Dict[str, Any]]:
        row = self.db.execute("SELECT elements FROM waf_profiles WHERE host=?", (host,)).fetchone()
        return json.loads(row["elements"] or "[]") if row else []

    def record(self, host, element, kind="char", paired_with="", location="query",
               content_type="text/html", outcome="allowed", marker="", note="") -> Dict[str, Any]:
        if not isinstance(host, str) or not host:
            raise ValueError("host is required")
        if outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {OUTCOMES}")
        if location not in LOCATIONS:
            raise ValueError(f"location must be one of {LOCATIONS}")
        if not isinstance(element, str) or not 1 <= len(element) <= 200:
            raise ValueError("element must be a 1..200 character probe string")
        host = host.lower()
        elements = self._elements(host)
        if not self.db.execute("SELECT 1 FROM waf_profiles WHERE host=?", (host,)).fetchone():
            self._upsert(host, {"kind": "unobserved", "status": None, "template_sha": None,
                                "markers_hit": [], "added_headers": [],
                                "notes": "no observe() baseline yet; outcomes still usable"})
        if len(elements) >= MAX_ELEMENTS_PER_HOST:
            raise ValueError(f"at most {MAX_ELEMENTS_PER_HOST} recorded outcomes per host")
        elements.append({"element": element, "kind": kind, "paired_with": paired_with,
                         "location": location, "content_type": content_type,
                         "outcome": outcome, "marker": marker, "note": note[:300],
                         "recorded": now()})
        self.db.execute("UPDATE waf_profiles SET elements=?, updated=? WHERE host=?",
                        (json.dumps(elements), now(), host))
        self.db.commit()
        return {"host": host, "element": element, "outcome": outcome,
                "recorded_outcomes": len(elements)}

    def show(self, host) -> Dict[str, Any]:
        row = self.db.execute("SELECT * FROM waf_profiles WHERE host=?", (host.lower(),)).fetchone()
        if row is None:
            raise ValueError(f"no WAF profile for host {host!r}; observe or record first")
        elements = json.loads(row["elements"] or "[]")
        allowed_chars = sorted({e["element"] for e in elements
                                if e["outcome"] == "allowed" and len(e["element"]) == 1})
        blocked = sorted({e["element"] for e in elements
                          if e["outcome"] in ("blocked", "stripped")})
        return {"host": host.lower(), "signature": json.loads(row["signature"] or "{}"),
                "surviving_chars": allowed_chars, "blocked_elements": blocked,
                "outcomes": [{"element": e["element"], "location": e["location"],
                              "content_type": e["content_type"], "outcome": e["outcome"]}
                             for e in elements[-100:]],
                "updated": row["updated"],
                "basis": "element table recorded per host/location/content-type; feeds the "
                         "payload context packet and the probe ladders"}
