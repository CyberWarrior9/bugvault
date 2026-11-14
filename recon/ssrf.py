"""Offline SSRF workflow, contextual case ledger and artifact/event correlation.

No network clients, payload execution, browser actions, cloud SDKs or finding
promotion. Captures and attribution remain operator-supplied evidence, not truth.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from .callbacks import (MAX_ARTIFACT, approved_callback_host, local_bytes, timestamp,
                        valid_marker, verified_bytes)
from .campaign import HTTP_METHODS, norm_host
from .extract import endpoint_key
from .planning import digest, scope_revision
from .score import applicable_classes, is_inferred_only
from .store import now

CONTEXT_FIELDS = {"request_url", "method", "account", "role", "tenant", "workflow", "field"}
STATES = ("observed", "negative", "blocked", "inconclusive", "not-applicable")

# id, branch, description. DEPTH_BRANCHES need a campaign depth grant copied from
# the program's written rules; the grant encodes program permission, nothing more.
CASES = (
    ("baseline", "base", "Capture the normal browser action, exact field, account/role/tenant and intended destination policy"),
    ("fetch-control", "base", "Unique controlled HTTP canary plus a negative control; distinguish an intended webhook from a boundary violation"),
    ("attribution", "base", "Attribute DNS/HTTP events to the application, not the browser, analyst, scanner or resolver alone"),
    ("response-read", "base", "Look for a server-returned canary absent from the initiating request, not URL reflection"),
    ("blind-async", "base", "Bound the worker/queue callback window; test cache/retry effects and fresh tokens; silence is inconclusive"),
    ("input-locations", "base", "Review query, nested JSON, form, multipart, stored URLs, Referer analytics, XML/media references and applicable GraphQL fields"),
    ("method-header-body", "base", "Measure actual outbound method/header/body control and credential forwarding using only test-account data"),
    ("parser-authority", "validation", "Compare validator and fetcher parsing: authority/userinfo, backslash, fragment, port, scheme and duplicate parameters"),
    ("parser-encoding", "validation", "Test bounded encoding, Unicode/IDNA, dot and case normalization variants against a controlled receiver"),
    ("ip-representation", "validation", "Where relevant compare canonical/numeric/short/mixed IPv4, IPv6 and mapped forms; never assume universal parser support"),
    ("path-extension", "validation", "Check path/extension allowlists and normalization without changing the approved destination"),
    ("redirect-hop", "validation", "Use a bounded controlled redirect chain; distinguish initial validation from validation at every hop"),
    ("redirect-method", "validation", "Observe method/header handling across redirects, including HTTP/HTTPS transitions; do not leak real credentials"),
    ("dns-cname", "validation", "Compare name/CNAME resolution and all returned addresses with the fetch destination, using controlled DNS"),
    ("dns-rebinding", "dns", "DNS-race comparison with controlled DNS and bounded resolution/redirect counts; needs the dns depth grant or equivalent written allowance"),
    ("render-media", "renderer", "Inspect server PDF/image/video/HTML/SVG/XML fetches with harmless remote assets; JS capability is not assumed"),
    ("internal-canary", "internal", "Reach an exact supplied internal host/port/path canary with a direct-access negative control; swap host/port/protocol freely within the granted internal scope"),
    ("internal-auth", "internal", "Check a demonstrated internal trust boundary on supplied test resources; banner/status is not authorization impact"),
    ("aws-imds", "cloud", "Establish EC2/IMDS version and token/method/header prerequisites; start with approved non-secret metadata"),
    ("gcp-metadata", "cloud", "Establish Compute metadata context and Metadata-Flavor header support; do not assume legacy beta endpoints work"),
    ("azure-metadata", "cloud", "Establish VM vs App Service context, Metadata header, API version and any platform-specific identity prerequisites"),
    ("container-other-cloud", "cloud", "Exercise ECS/Lambda/other-provider credential endpoints when that deployment is the affected worker; credential IDs come from observed metadata, never guessing"),
    ("file-protocol", "protocol", "file-scheme read of a planted file (lab default) or an authorized target path under the protocol grant; distinguish file read from HTTP SSRF"),
    ("cross-protocol", "protocol", "Exercise non-HTTP schemes (file, gopher, dict, ftp, ldap, ...) against controlled receivers; internal services need the internal grant, service writes an explicit program allowance"),
    ("sni-tls", "protocol", "Record SNI/TLS-routing hypotheses; the current browser/MCP cannot craft arbitrary TLS handshakes, so block unsupported cases"),
    ("platform-chain", "platform", "Confirm exact product/version/config/sink before a harmless platform-specific check; old CVE tables are leads, not proof"),
    ("credential-use", "credential", "Read credentials reached via an observed cloud/internal case, then demonstrate unlock on a supplied test resource; broad enumeration or persistence needs its own program allowance"),
    ("execution-chain", "execution", "Inert execution canary after exact sink prerequisites; owned lab by default, or any target when the program's rules explicitly cover execution proofs"),
    ("replay-report", "base", "Clean replay, distinct negative control, minimal demonstrated impact, root-cause dedup and all reportability answers"),
)
CASE_BY_ID = {row[0]: row for row in CASES}

# Branches gated by campaign depth grants vs standard authorized testing. Grants are
# the program's rules encoded once; they add no permission the program did not give.
DEPTH_BRANCHES = ("dns", "internal", "cloud", "credential", "protocol", "execution")
OPEN_BRANCHES = ("base", "validation", "renderer", "platform")

# Observed source case -> cases whose prerequisites it satisfies (chain edges).
CHAIN_EDGES = {
    "fetch-control": ("parser-authority", "parser-encoding", "ip-representation", "path-extension",
                      "redirect-hop", "redirect-method", "dns-cname", "render-media", "platform-chain",
                      "internal-canary", "aws-imds", "gcp-metadata", "azure-metadata",
                      "container-other-cloud", "file-protocol", "cross-protocol"),
    "attribution": ("blind-async",),
    "response-read": ("render-media", "platform-chain", "internal-auth"),
    "method-header-body": ("aws-imds", "gcp-metadata", "azure-metadata", "cross-protocol"),
    "internal-canary": ("internal-auth",),
    "aws-imds": ("credential-use",),
    "gcp-metadata": ("credential-use",),
    "azure-metadata": ("credential-use",),
    "container-other-cloud": ("credential-use",),
    "file-protocol": ("credential-use",),
    "cross-protocol": ("execution-chain",),
    "credential-use": ("execution-chain", "replay-report"),
}


def granted_branches(config):
    """Read ssrf.depth_grants: ["all"] or a subset of DEPTH_BRANCHES, no repeats."""
    grants = config.get("depth_grants", [])
    if not isinstance(grants, list) or not all(isinstance(g, str) and g for g in grants):
        raise ValueError('ssrf.depth_grants must be a list of branch names or ["all"]')
    unknown = [g for g in grants if g != "all" and g not in DEPTH_BRANCHES]
    if unknown:
        raise ValueError(f'unknown ssrf.depth_grants entries {unknown}; '
                         f'valid: {list(DEPTH_BRANCHES)} or "all"')
    if len(set(grants)) != len(grants):
        raise ValueError("ssrf.depth_grants must not repeat entries")
    return set(DEPTH_BRANCHES) if "all" in grants else set(grants)
SCHEMA = """
CREATE TABLE IF NOT EXISTS ssrf_case_events(
 id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
 context TEXT NOT NULL, context_sha256 TEXT NOT NULL, scope_sha256 TEXT NOT NULL,
 asset_sha256 TEXT NOT NULL, case_id TEXT NOT NULL, state TEXT NOT NULL,
 requests_declared INTEGER NOT NULL, note TEXT NOT NULL, artifacts TEXT NOT NULL,
 created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ssrf_context ON ssrf_case_events(asset_id,context_sha256,id);
"""


def context_value(value=None):
    if value is None:
        return {k: "" for k in sorted(CONTEXT_FIELDS)}
    if not isinstance(value, dict) or set(value) != CONTEXT_FIELDS:
        raise ValueError(f"context fields must be exactly {sorted(CONTEXT_FIELDS)}")
    if any(not isinstance(v, str) or not v.strip() or len(v) > (4000 if k == "request_url" else 200)
           or any(ord(c) < 32 for c in v) for k, v in value.items()):
        raise ValueError("context values must be non-empty single-line strings (labels <=200, URL <=4000)")
    result = {k: v.strip() for k, v in value.items()}
    result["method"] = result["method"].upper()
    if result["method"] not in HTTP_METHODS:
        raise ValueError("context method is not supported")
    return result


def read_json(path):
    with Path(path).open("rb") as stream:
        data = stream.read(1_000_001)
    if len(data) > 1_000_000:
        raise ValueError("SSRF JSON input exceeds one megabyte")
    return json.loads(data)


class SSRFWorkflow:
    def __init__(self, ctx):
        self.ctx = ctx
        self.db = ctx.store.db
        self.db.executescript(SCHEMA)

    def _asset(self, asset_id):
        if type(asset_id) is not int or asset_id < 1:
            raise ValueError("asset ID must be a positive integer")
        asset = self.ctx.store.get_asset(asset_id)
        if asset["kind"] != "endpoint" or urlsplit(asset["value"]).scheme not in ("http", "https"):
            raise ValueError("SSRF workflow requires an endpoint asset")
        self.ctx.scope.check(asset["value"])
        if is_inferred_only(asset):
            raise ValueError("an inferred-only endpoint needs observed surface evidence first")
        return asset

    def _context(self, asset, context, required=False):
        if required and context is None:
            raise ValueError("record/correlate requires an exact context")
        result = context_value(context)
        if result["request_url"]:
            self.ctx.scope.check(result["request_url"])
            if endpoint_key(result["request_url"]) != asset["value"]:
                raise ValueError("context request URL does not match the endpoint family")
        return result

    def _config(self):
        config = self.ctx.campaign.raw.get("ssrf", {})
        if not isinstance(config, dict):
            raise ValueError("ssrf config must be an object")
        return config

    def plan(self, asset_id, context=None):
        asset = self._asset(asset_id)
        context = self._context(asset, context)
        config = self._config()
        cap = config.get("per_case_effort_cap", 3)
        if type(cap) is not int or not 1 <= cap <= 10:
            raise ValueError("ssrf.per_case_effort_cap must be 1..10")
        granted = granted_branches(config)
        blockers = []
        if self.ctx.policy.mode == "passive":
            blockers.append("passive mode: no live target requests")
        if "ssrf" in self.ctx.campaign.raw.get("excluded_bug_classes", []):
            blockers.append("SSRF is excluded by campaign rules")
        if not all(context.values()):
            blockers.append("supply exact request_url/method/account/role/tenant/workflow/field context; use explicit none/anonymous labels")
        elif context["method"] not in self.ctx.policy.allowed_methods:
            blockers.append("method is not granted by policy.allowed_methods")
        revision, asset_hash = scope_revision(self.ctx), digest(asset)
        rows = self.db.execute("SELECT * FROM ssrf_case_events WHERE asset_id=? AND context_sha256=? "
                               "ORDER BY id", (asset_id, digest(context))).fetchall()
        current = [r for r in rows if r["scope_sha256"] == revision and r["asset_sha256"] == asset_hash]
        latest = {r["case_id"]: r for r in current}
        counts = Counter(r["case_id"] for r in current if r["requests_declared"] > 0)
        observed = {r["case_id"] for r in current if r["state"] == "observed"}
        cards = []
        for case_id, branch, description in CASES:
            row = latest.get(case_id)
            artifacts = json.loads(row["artifacts"]) if row else []
            integrity = "not-supplied"
            if artifacts:
                try:
                    for ref in artifacts:
                        verified_bytes(self.ctx.campaign.root, {k: ref[k] for k in ("path", "sha256")})
                    integrity = "hashes-match"
                except (ValueError, OSError, KeyError):
                    integrity = "missing-or-modified"
            authorization = "standard" if branch in OPEN_BRANCHES else (
                "granted" if branch in granted else "grant-required")
            gate = {
                "standard": "verify browser/control/routing, scope, budgets and case prerequisites before any action",
                "granted": f"{branch} depth granted by campaign ssrf.depth_grants; scope-check every "
                           "destination; live actions still run in the dedicated browser through Burp",
                "grant-required": f"add {branch} to campaign ssrf.depth_grants (copied from the program's "
                                  "written rules) before working this case",
            }[authorization]
            satisfied = sorted(src for src, deps in CHAIN_EDGES.items()
                               if case_id in deps and src in observed)
            cards.append({"id": case_id, "branch": branch, "description": description,
                          "state": row["state"] if row else "untested",
                          "event_id": row["id"] if row else None,
                          "artifacts": artifacts, "artifact_integrity": integrity,
                          "attempts_recorded": counts[case_id],
                          "effort_exhausted": counts[case_id] >= cap,
                          "note": row["note"] if row else "",
                          "authorization": authorization, "gate": gate,
                          "prerequisites_satisfied_by": satisfied,
                          "chain_ready": bool(satisfied)})
        return {"schema_version": 1, "asset_id": asset_id, "url": asset["value"],
                "scope_sha256": revision, "asset_sha256": asset_hash, "context": context,
                "skill": "hunt-ssrf", "candidate_reason": applicable_classes(asset).get("ssrf", "manual surface hypothesis"),
                "blockers": blockers, "cases": cards, "per_case_effort_cap": cap,
                "depth_grants": sorted(granted), "depth_branches": list(DEPTH_BRANCHES),
                "chain_next": [c["id"] for c in sorted(
                    (c for c in cards if c["state"] in ("untested", "blocked", "inconclusive")
                     or c["artifact_integrity"] == "missing-or-modified"),
                    key=lambda c: (not c["chain_ready"],
                                   c["authorization"] == "grant-required",
                                   c["effort_exhausted"],
                                   -len(c["prerequisites_satisfied_by"])))[:8]],
                "unresolved_cases": sum(c["state"] in ("untested", "blocked", "inconclusive")
                                        or c["artifact_integrity"] == "missing-or-modified" for c in cards),
                "events_retained": len(rows),
                "stale_events_retained": len(rows) - len(current),
                "external_requests_declared": sum(r["requests_declared"] for r in rows),
                "execution": "offline only; no browser/HTTP/DNS/cloud actions; this plan grants no execution",
                "evidence_basis": "operator-recorded outcomes, not independently verified test completeness",
                "budget_basis": "declared counts in this context only; not enforced or debited from native budgets",
                "gate_basis": "depth grants are campaign config copied from program rules; browser routing, "
                              "destination scope and case prerequisites still require manual verification",
                "finding_promoted": False}

    def record(self, asset_id, context, case_id, state, note, artifacts=(), requests_declared=0):
        asset = self._asset(asset_id)
        context = self._context(asset, context, required=True)
        if case_id not in CASE_BY_ID or state not in STATES:
            raise ValueError("unknown SSRF case or outcome")
        if not isinstance(note, str) or not 1 <= len(note.strip()) <= 2000:
            raise ValueError("every outcome needs a note of 1..2000 characters")
        if type(requests_declared) is not int or not 0 <= requests_declared <= 10000:
            raise ValueError("declared request count must be 0..10000")
        if not isinstance(artifacts, (tuple, list)) or len(artifacts) > 8:
            raise ValueError("at most eight artifacts per event")
        blobs = [local_bytes(self.ctx.campaign.root, p) for p in artifacts]
        hashes = {hashlib.sha256(data).hexdigest() for data in blobs}
        if state in ("observed", "negative") and (len(hashes) < 2 or requests_declared < 1):
            raise ValueError("observed/negative needs distinct replay/control artifacts and a request count")
        dest = self.ctx.campaign.state_dir / "ssrf-evidence"
        if dest.is_symlink() or self.ctx.campaign.state_dir.is_symlink():
            raise ValueError("refusing a symlinked evidence store")
        kept = []
        for data in blobs:
            sha = hashlib.sha256(data).hexdigest()
            dest.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = dest / sha
            if path.exists() or path.is_symlink():
                if path.is_symlink() or local_bytes(self.ctx.campaign.root, path.resolve()) != data:
                    raise ValueError("stored SSRF evidence was modified")
            else:
                with path.open("xb") as stream:
                    stream.write(data)
                path.chmod(0o600)
            kept.append({"path": path.relative_to(self.ctx.campaign.root).as_posix(),
                         "sha256": sha, "bytes": len(data)})
        cur = self.db.execute("INSERT INTO ssrf_case_events(asset_id,context,context_sha256,scope_sha256,"
                              "asset_sha256,case_id,state,requests_declared,note,artifacts,created) "
                              "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (asset_id, json.dumps(context), digest(context),
                              scope_revision(self.ctx), digest(asset), case_id, state, requests_declared,
                              note.strip(), json.dumps(kept), now()))
        self.db.commit()
        return {"event_id": cur.lastrowid, "case_id": case_id, "state": state,
                "artifacts": kept, "basis": "operator assertion; validator must inspect artifacts",
                "executed": False, "finding_promoted": False}

    def correlate(self, asset_id, bundle):
        """Check normalized, hash-bound external evidence without declaring SSRF proven."""
        asset = self._asset(asset_id)
        expected = {"schema_version", "asset_id", "request_url", "context", "attempt_id", "started_at", "ended_at",
                    "callback_url", "request", "response", "control", "response_canary", "events"}
        if not isinstance(bundle, dict) or set(bundle) != expected or type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1:
            raise ValueError("invalid normalized SSRF evidence bundle fields/version")
        if type(bundle["asset_id"]) is not int or bundle["asset_id"] != asset_id:
            raise ValueError("bundle belongs to another asset")
        context = self._context(asset, bundle["context"], required=True)
        if bundle["request_url"] != context["request_url"]:
            raise ValueError("bundle request URL does not match its exact context")
        marker = bundle["attempt_id"]
        if not valid_marker(marker):
            raise ValueError("attempt_id must be a fresh 16..96-character marker")
        start, end = timestamp(bundle["started_at"]), timestamp(bundle["ended_at"])
        if not 0 <= end - start <= 600:
            raise ValueError("callback evidence window must be ordered and at most 600 seconds")
        if not isinstance(bundle["callback_url"], str) or any(c.isspace() for c in bundle["callback_url"]):
            raise ValueError("callback URL must be a single URL string")
        callback = urlsplit(bundle["callback_url"])
        if callback.scheme not in ("http", "https") or not callback.hostname or callback.username is not None or callback.fragment:
            raise ValueError("callback URL must be a plain HTTP(S) URL")
        if callback.port is not None and not 1 <= callback.port <= 65535:
            raise ValueError("invalid callback port")
        hosts = self._config().get("callback_hosts", [])
        host = norm_host(callback.hostname)
        approved = approved_callback_host(hosts, host)
        if not approved:
            raise ValueError("callback host has no explicit ssrf.callback_hosts grant")
        if marker.lower() not in (host + callback.path).lower():
            raise ValueError("callback must bind the attempt marker in host/path")
        root = self.ctx.campaign.root
        cache, total_bytes = {}, 0

        def verified(ref):
            nonlocal total_bytes
            key = json.dumps(ref, sort_keys=True)
            if key not in cache:
                data = verified_bytes(root, ref)
                total_bytes += len(data)
                if total_bytes > 25_000_000:
                    raise ValueError("correlation artifacts exceed 25 megabytes")
                cache[key] = data
            return cache[key]

        request = verified(bundle["request"])
        response = verified(bundle["response"])
        control = verified(bundle["control"])
        if bundle["response"]["sha256"] == bundle["control"]["sha256"]:
            raise ValueError("response and negative control must be distinct")
        if marker.encode() not in request or host.encode() not in request.lower():
            raise ValueError("initiating request capture does not contain the bound callback marker/host")
        events = bundle["events"]
        if not isinstance(events, list) or len(events) > 2000:
            raise ValueError("events must be a bounded normalized list")
        matched, seen, ignored = [], {}, Counter()
        for event in events:
            keys = {"id", "attempt_id", "timestamp", "hostname", "protocol", "origin", "artifact"}
            if not isinstance(event, dict) or set(event) != keys or not all(
                    isinstance(event[k], str) and 0 < len(event[k]) <= 400 for k in keys - {"artifact"}):
                raise ValueError("invalid normalized callback event")
            raw = verified(event["artifact"])
            if event["id"] in seen:
                if seen[event["id"]] != digest(event):
                    raise ValueError("conflicting duplicate callback ID")
                ignored["duplicate"] += 1
                continue
            seen[event["id"]] = digest(event)
            if event["attempt_id"] != marker or norm_host(event["hostname"]) != host:
                ignored["other-attempt-or-host"] += 1
            elif not start <= timestamp(event["timestamp"]) <= end:
                ignored["outside-window"] += 1
            elif event["origin"] not in ("application", "unknown"):
                ignored["browser-analyst-scanner-or-invalid-origin"] += 1
            elif event["protocol"] not in ("dns", "http", "https"):
                ignored["other-protocol"] += 1
            elif marker.encode() not in raw or host.encode() not in raw.lower():
                ignored["marker-absent-from-raw-event"] += 1
            else:
                matched.append(event)
        attributed = [e for e in matched if e["origin"] == "application"]
        http = [e for e in attributed if e["protocol"] in ("http", "https")]
        assessment = ("http-interaction-correlated" if http else "dns-interaction-correlated" if attributed
                      else "unattributed-interaction" if matched else "no-correlated-interaction")
        canary = bundle["response_canary"]
        if not isinstance(canary, str) or (canary and not 16 <= len(canary.encode()) <= 1024):
            raise ValueError("response_canary must be empty or 16..1024 bytes")
        readback = bool(canary and http and canary.encode() in response and canary.encode() not in request
                        and canary.encode() not in control)
        return {"asset_id": asset_id, "context": context, "attempt_id": marker, "assessment": assessment,
                "matched_event_ids": [e["id"] for e in matched], "ignored": dict(ignored),
                "response_canary_observed": readback, "finding_promoted": False, "executed": False,
                "warnings": ["Event origin is operator-supplied, not independently certified.",
                             "DNS/HTTP interaction or raw byte presence does not establish an unauthorized boundary or impact.",
                             "No callback is inconclusive, not proof of safety. Burp/export IDs are not native fact-check IDs."]}
