"""Offline, fail-closed inventory of stored JS/map responses. No probes or findings.

This first ledger slice reconciles imported and native captures. It does not claim
complete per-build coverage, an executable secret, or a confirmed vulnerability.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .extract import (SECRET_PATTERNS, endpoint_key, extract_from_js, origin_of, path_ext,
                      query_keys, sourcemap_sources)
from .factcheck import ResponseFacts, response_hash

EXTRACTOR = "js-inventory-v1"
MAX_ASSETS = 3000
MAX_LEADS = 10_000
PRIVILEGED = {"stripe-live-secret", "github-token", "slack-token", "private-key",
              "supabase-secret"}


def jwt_metadata(value: str) -> dict:
    """Value-free, unverified header/claim hints. No signature validation."""
    try:
        header, body, _ = value.split(".", 2)
        h = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
        p = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if not isinstance(h, dict) or not isinstance(p, dict):
            return {}
        def safe(v):
            return v if isinstance(v, str) and len(v) <= 100 and all(
                c.isalnum() or c in " .:/_-" for c in v) else ""
        return {"alg": safe(h.get("alg")), "typ": safe(h.get("typ")),
                "role": safe(p.get("role")), "iss": safe(p.get("iss")),
                "aud": safe(p.get("aud")), "exp": p.get("exp") if type(p.get("exp")) is int else None,
                "sub_sha256": hashlib.sha256(p["sub"].encode()).hexdigest() if
                isinstance(p.get("sub"), str) else "", "signature_verified": False}
    except (ValueError, TypeError, UnicodeDecodeError, KeyError):
        return {}


def secret_class(kind: str, value: str) -> str:
    """Offline format/claim classification, NEVER an issuer validity check."""
    if kind in ("google-api-key", "stripe-public", "supabase-publishable"):
        return "public-by-design"
    if kind == "jwt":
        try:
            role = jwt_metadata(value).get("role", "")
            if role == "anon":
                return "public-by-design"
            if role == "service_role":
                return "privileged-looking"
        except (ValueError, UnicodeDecodeError, TypeError):
            pass
        return "ambiguous"
    if kind == "aws-access-key-id":
        return "ambiguous"  # ID alone is not a working AWS access-key pair
    return "privileged-looking" if kind in PRIVILEGED else "ambiguous"


class JsInventory:
    def __init__(self, ctx):
        self.ctx, self.db, self.store = ctx, ctx.store.db, ctx.store
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS js_inventory_artifacts (
                request_id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL,
                origin TEXT NOT NULL, url TEXT NOT NULL, body_sha256 TEXT NOT NULL,
                response_sha256 TEXT NOT NULL, extractor TEXT NOT NULL,
                basis TEXT NOT NULL, complete INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS js_inventory_leads (
                lead_key TEXT PRIMARY KEY, asset_id INTEGER NOT NULL, family TEXT NOT NULL,
                subject TEXT NOT NULL, priority INTEGER NOT NULL, reason TEXT NOT NULL,
                disposition TEXT NOT NULL DEFAULT 'extracted');
            CREATE TABLE IF NOT EXISTS js_inventory_sightings (
                lead_key TEXT NOT NULL, request_id INTEGER NOT NULL,
                body_sha256 TEXT NOT NULL, PRIMARY KEY(lead_key,request_id));
        """)

    def _body(self, response: dict) -> bytes:
        sha = response["body_sha256"]
        if not sha or len(sha) != 64:
            raise ValueError(f"JS response {response['id']}: body unavailable")
        path = self.ctx.campaign.bodies_dir / sha
        try:
            data = path.read_bytes()
        except OSError as e:
            raise ValueError(f"JS response {response['id']}: stored body missing") from e
        if hashlib.sha256(data).hexdigest() != sha or len(data) != response["body_len"]:
            raise ValueError(f"JS response {response['id']}: stored body hash/length mismatch")
        return data

    def _lead(self, asset_id: int, request_id: int, sha: str, family: str,
              subject: str, priority: int, reason: str) -> None:
        key = "js:" + hashlib.sha256(f"{family}:{subject}".encode()).hexdigest()[:24]
        if self.db.execute("SELECT count(*) FROM js_inventory_leads").fetchone()[0] >= MAX_LEADS:
            raise ValueError("JS inventory lead cap reached; collection incomplete")
        self.db.execute("INSERT OR IGNORE INTO js_inventory_leads"
                        "(lead_key,asset_id,family,subject,priority,reason) VALUES(?,?,?,?,?,?)",
                        (key, asset_id, family, subject[:250], priority, reason))
        self.db.execute("INSERT OR IGNORE INTO js_inventory_sightings VALUES(?,?,?)",
                        (key, request_id, sha))

    def sync(self) -> Dict[str, Any]:
        facts = ResponseFacts(self.ctx)
        suffixes = ("js", "mjs", "cjs", "map")
        filters = " OR ".join(f"lower(r.url) GLOB '*.{ext}' OR lower(r.url) LIKE '%.{ext}?%'"
                              for ext in suffixes)
        rows = self.db.execute(
            "SELECT r.id FROM requests r JOIN response_capture c ON c.request_id=r.id "
            "WHERE r.status=200 AND r.error IS NULL AND r.body_sha256 IS NOT NULL "
            "AND (" + filters + ") ORDER BY r.id LIMIT ?", (MAX_ASSETS + 1,)).fetchall()
        if len(rows) > MAX_ASSETS:
            raise ValueError("JS inventory response cap reached; increase coverage explicitly")
        added = 0
        for row in rows:
            response = self.store.response(row["id"])
            url = response["url"]
            ext = path_ext(urlsplit(url).path)
            if ext not in ("js", "mjs", "cjs", "map") or not self.ctx.scope.is_in(url):
                continue
            sha = response["body_sha256"]
            previous = self.db.execute("SELECT body_sha256,extractor FROM js_inventory_artifacts "
                                       "WHERE request_id=?", (row["id"],)).fetchone()
            if previous and (previous["body_sha256"] != sha or previous["extractor"] != EXTRACTOR):
                raise ValueError(f"JS response {row['id']}: inventory snapshot changed; verify/review")
            data = self._body(response)  # fail closed even on a repeat sync
            if previous:
                continue
            kind = "sourcemap" if ext == "map" else "js"
            asset_id, _ = self.store.upsert_asset(
                kind, url.split("?", 1)[0], host=urlsplit(url).hostname, in_scope=True,
                attrs={"sources": ["js-inventory"], "imported_only": response["basis"] == "imported-burp-capture"})
            self.db.execute("INSERT INTO js_inventory_artifacts VALUES(?,?,?,?,?,?,?,?,?)",
                            (row["id"], asset_id, origin_of(url), url, sha, response_hash(response), EXTRACTOR,
                             response["basis"], int(bool(response["body_complete"]))))
            added += 1
            texts: List[str] = []
            if kind == "js":
                texts = [data.decode("utf-8", "replace")]
            else:
                if not response["body_complete"]:
                    self.store.add_fact(asset_id, "stored source map truncated or completeness unknown; "
                                        "JSON/exposure cannot be graded", "observed",
                                        kind="collection-gap", source="js-inventory")
                    self.db.commit()
                    continue
                try:
                    decoded = json.loads(data)
                except ValueError:
                    self.store.add_fact(asset_id, "stored source map is not valid JSON",
                                        "observed", kind="collection-gap", evidence=url,
                                        source="js-inventory")
                    continue
                if not isinstance(decoded, dict) or decoded.get("version") != 3:
                    continue
                texts = [source for _, source in sourcemap_sources(decoded)]
                status_fact = facts.add(row["id"], {"type": "status_is", "expected": 200}, asset_id)
                if status_fact["outcome"] == "supported":
                    marker = next((n for n in decoded.get("sources", [])
                                   if isinstance(n, str) and n and n.encode() in data), "")
                    if marker:
                        facts.add(row["id"], {"type": "body_contains_raw", "marker": marker[:120]}, asset_id)
                    self.store.seed_coverage(asset_id, {"info-disclosure":
                        "fetched source map; exposure alone is not a vulnerability"})
                    self._lead(asset_id, row["id"], sha, "map-exposure", url, 1,
                               "source map served; exposure alone is never a finding")
            for text in texts[:3000]:
                found = extract_from_js(text)
                for endpoint in found.endpoints:
                    raw = endpoint.raw
                    target = (raw if raw.startswith(("http://", "https://", "ws://", "wss://")) else
                              "https:" + raw if raw.startswith("//") else
                              origin_of(url) + raw if raw.startswith("/") else "")
                    if target:
                        if any(pattern.search(target) for pattern in SECRET_PATTERNS.values()):
                            self.store.add_fact(asset_id, "JS operation URL contains a token-like "
                                                "path or query; URL withheld from endpoint inventory",
                                                "inferred", kind="collection-gap", source="js-inventory")
                            continue
                        if self.ctx.add_endpoint(target, "js-inventory", method=endpoint.method,
                                                 params=endpoint.params,
                                                 extra={"basis": "static-reference"}) is None:
                            continue
                        self._lead(asset_id, row["id"], sha, "operation",
                                   (endpoint.method or "UNKNOWN") + " " + endpoint_key(target)
                                   + ("?" + "&".join(query_keys(target)) if query_keys(target) else ""), 2,
                                   "operation referenced in a stored client artifact; authorization untested")
                for label, pattern in SECRET_PATTERNS.items():
                    for match in list(pattern.finditer(text))[:200]:
                        value = match.group(0)
                        classification = secret_class(label, value)
                        value_hash = hashlib.sha256(value.encode()).hexdigest()
                        # Hash and class only: no raw secret, prefix or source snippet in SQLite.
                        subject = label + ":" + value_hash
                        self._lead(asset_id, row["id"], sha, "secret", subject,
                                   0 if classification == "privileged-looking" else 4,
                                   classification + "; validity/impact untested")
                        if classification != "public-by-design" and kind == "js":
                            marker = value[:6]
                            if facts.add(row["id"], {"type": "body_contains_raw",
                                                     "marker": marker}, asset_id)["outcome"] == "supported":
                                self.store.seed_coverage(asset_id, {"info-disclosure":
                                    "privileged-looking or ambiguous client secret; validity untested"})
            self.db.commit()
        return {"added": added, "total": self.db.execute(
            "SELECT count(*) FROM js_inventory_artifacts").fetchone()[0],
                "executed": False, "complete": False,
                "note": "stored-response inventory only; uncollected chunks, roles and stages remain open"}

    def verify(self) -> Dict[str, Any]:
        problems = []
        for r in self.db.execute("SELECT * FROM js_inventory_artifacts ORDER BY request_id"):
            try:
                response = self.store.response(r["request_id"])
                if (response["body_sha256"] != r["body_sha256"] or
                        response_hash(response) != r["response_sha256"]):
                    raise ValueError("response snapshot changed")
                self._body(response)
            except (ValueError, KeyError) as e:
                problems.append({"request_id": r["request_id"], "reason": str(e)})
        return {"ok": not problems, "problems": problems[:100], "executed": False}

    def status(self, limit: int = 30) -> Dict[str, Any]:
        if not 1 <= limit <= 100:
            raise ValueError("JS status limit must be 1..100")
        leads = [dict(r) for r in self.db.execute(
            "SELECT lead_key,family,subject,priority,reason,disposition FROM js_inventory_leads "
            "ORDER BY priority,lead_key LIMIT ?", (limit,))]
        return {"artifacts": self.db.execute("SELECT count(*) FROM js_inventory_artifacts").fetchone()[0],
                "leads": leads, "integrity": self.verify(), "complete": False,
                "stage_gap": "full build reconciliation and handoff ledger not implemented",
                "executed": False}
