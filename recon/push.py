"""Fail-closed, offline review of hunt-push manifests; never sends a request.

Unlike planning.py's discovery jobs, a push is a class/asset/operation/evidence
intent. Apply records a snapshot-bound approval for a *future* executor, not a
traffic grant. The existing `recon send` command is not coupled to this record.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from .campaign import PolicyViolation, norm_host
from .catalog import HUNT_SKILLS
from .engagement import Engagement, _atomic_json
from .extract import endpoint_key, origin_of
from .factcheck import validate_predicate
from .planning import digest, scope_revision
from .skillmap import SKILLS_FOR_CLASS, skill_path
from .store import now

MAX_BYTES = 1_000_000
MAX_PUSHES = 20
PUSH_FIELDS = {"class", "asset_id", "asset_sha256", "endpoint", "method", "skill",
               "model", "intent", "predicate", "poe_target", "request_budget",
               "debt_items", "reason"}


def budget_snapshot(ctx) -> dict:
    """Only the existing enforceable campaign/run counters; no fake hourly quota."""
    attempts = ctx.store.network_attempts()
    return {"network_attempts": attempts,
            "remaining_campaign": max(0, ctx.policy.max_campaign_requests - attempts),
            "max_requests_per_run": ctx.policy.max_requests,
            "scope_sha256": scope_revision(ctx)}


def context(ctx, engagement: Engagement) -> dict:
    engagement.require_current()
    debt = engagement.reconcile()
    assets = []
    candidates = [a for a in ctx.store.assets(in_scope=True)
                  if a["kind"] in ("endpoint", "service") and
                  (ctx.scope.is_in(a["value"]) if a["kind"] == "endpoint" else
                   any(ctx.scope.is_in(url) for url in
                       (a["attrs"].get("entry_urls") or [a["value"] + "/"])))]
    for a in candidates[:100]:
        assets.append({"asset_id": a["id"], "asset_sha256": digest(a),
                       "kind": a["kind"], "value": a["value"]})
    budget = budget_snapshot(ctx)
    return {"schema_version": 1, "scope_sha256": scope_revision(ctx),
            "budget_sha256": digest(budget), "budget": budget,
            "debt": debt["items"][:100], "debt_total": len(debt["items"]),
            "assets": assets, "assets_truncated": max(0, len(candidates) - 100),
            "required_push_fields": sorted(PUSH_FIELDS),
            "notice": "Offline planning context. Hourly pool, external traffic and unattended "
                      "execution are NOT enforced here; do not use this as a traffic grant."}


def _text(value, field: str, size: int = 1000) -> str:
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= size:
        raise ValueError(f"{field} must be 1..{size} characters")
    return value


def _asset_matches(ctx, asset: dict, endpoint: str) -> bool:
    if asset["kind"] == "endpoint":
        return endpoint_key(asset["value"]) == endpoint_key(endpoint)
    if asset["kind"] == "service":
        return origin_of(asset["value"]) == origin_of(endpoint)
    if asset["kind"] in ("domain", "host"):
        return norm_host(asset["value"]) == norm_host(urlsplit(endpoint).hostname or "")
    return False


def review(ctx, path: Path, engagement: Engagement, *, apply: bool = False) -> dict:
    engagement.require_current()
    with Path(path).open("rb") as stream:
        content = stream.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ValueError("push manifest exceeds one megabyte")
    data = json.loads(content)
    if not isinstance(data, dict) or set(data) != {
            "schema_version", "scope_sha256", "budget_sha256", "pushes"}:
        raise ValueError("push manifest must have only schema_version, scope_sha256, "
                         "budget_sha256 and pushes")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1 \
            or data["scope_sha256"] != scope_revision(ctx):
        raise ValueError("push manifest schema/scope snapshot is stale or invalid")
    budget = budget_snapshot(ctx)
    if data["budget_sha256"] != digest(budget):
        raise ValueError("push manifest budget snapshot is stale")
    if not isinstance(data["pushes"], list) or not 1 <= len(data["pushes"]) <= MAX_PUSHES:
        raise ValueError(f"pushes must be a list of 1..{MAX_PUSHES} operations")
    if not ctx.policy.allows("active"):
        raise PolicyViolation("target hunt pushes need active campaign mode")
    debt = engagement.reconcile()
    debt_by_id = {item["id"]: item for item in debt["items"]}
    blocked = engagement.blocked_hosts()
    allowed_skills = {s for s, _ in HUNT_SKILLS}
    checked, seen, total = [], set(), 0
    for item in data["pushes"]:
        if not isinstance(item, dict) or set(item) != PUSH_FIELDS:
            raise ValueError("push fields must match the closed schema (including exact method)")
        cls = _text(item["class"], "class", 64)
        skill = _text(item["skill"], "skill", 64)
        if cls not in SKILLS_FOR_CLASS or skill not in SKILLS_FOR_CLASS[cls] \
                or skill not in allowed_skills or not skill_path(skill).is_file():
            raise ValueError("push class/skill is not a routed, installed hunt capability")
        if type(item["asset_id"]) is not int or item["asset_id"] < 1:
            raise ValueError("push asset_id must be a positive integer")
        asset = ctx.store.get_asset(item["asset_id"])
        if not asset["in_scope"] or item["asset_sha256"] != digest(asset):
            raise ValueError("push asset snapshot is stale or out of scope")
        endpoint = _text(item["endpoint"], "endpoint", 4096)
        url = urlsplit(endpoint)
        if url.scheme not in ("http", "https") or not url.hostname or url.username \
                or url.password or url.fragment or not ctx.scope.is_in(endpoint) \
                or not _asset_matches(ctx, asset, endpoint):
            raise PolicyViolation("push endpoint must be an exact scoped HTTP(S) operation of its asset")
        if url.hostname in blocked:
            raise PolicyViolation(f"push host is deferred ({blocked[url.hostname]['reason']}); do not retry")
        method = _text(item["method"], "method", 10)
        if method not in ctx.policy.allowed_methods:
            raise PolicyViolation(f"push method {method} is not granted by policy.allowed_methods")
        _text(item["model"], "model", 120)
        _text(item["intent"], "intent")
        _text(item["reason"], "reason")
        validate_predicate(item["predicate"])
        if type(item["poe_target"]) is not int or not 1 <= item["poe_target"] <= 4:
            raise ValueError("push poe_target must be an integer 1..4")
        amount = item["request_budget"]
        if type(amount) is not int or amount < 1:
            raise ValueError("push request_budget must be a positive integer")
        if not isinstance(item["debt_items"], list) or not 1 <= len(item["debt_items"]) <= 10 \
                or len(set(map(str, item["debt_items"]))) != len(item["debt_items"]):
            raise ValueError("push needs 1..10 distinct current debt references")
        for ref in item["debt_items"]:
            if not isinstance(ref, str) or ref not in debt_by_id:
                raise ValueError("push references absent or resolved debt")
            row = debt_by_id[ref]
            if row.get("blocked_reason") or row["kind"] == "blocked-host":
                raise PolicyViolation("push cannot fund a blocked debt item")
            if row["kind"] in ("coverage", "retag") and (
                    row["asset_id"] != asset["id"] or row["class"] != cls):
                raise ValueError("push coverage/retag debt must match asset and class")
            if row["kind"] == "matrix":
                from .fields import module_of
                if module_of(endpoint) != row["module"]:
                    raise ValueError("push matrix debt must match the operation module")
            if row["kind"] == "surface" and (
                    row["asset_id"] != asset["id"] or row["class"] != cls):
                raise ValueError("push render-surface debt must match the asset and class")
            if row["kind"] == "auth-case" and (
                    row["asset_id"] != asset["id"] or cls != "security-misconfiguration"
                    or row["method"] != method or row["endpoint"] != endpoint):
                raise ValueError("push auth-case debt must match exact asset/method/endpoint")
            if row["kind"] == "chain" and row["class"] != cls:
                raise ValueError("push chain debt must match its frontier class")
        key = (cls, asset["id"], endpoint, method)
        if key in seen:
            raise ValueError("duplicate class/asset/endpoint/method push")
        seen.add(key)
        total += amount
        checked.append({"class": cls, "asset_id": asset["id"], "endpoint": endpoint,
                        "method": method, "skill": skill, "request_budget": amount})
    if total > min(budget["remaining_campaign"], budget["max_requests_per_run"]):
        raise PolicyViolation("push batch exceeds remaining persistent campaign or single-run cap")
    sha = hashlib.sha256(content).hexdigest()
    if apply:
        # An offline approval receipt; no existing sender consumes this receipt.
        _atomic_json(engagement.path / "push-authorizations" / f"{sha}.json",
                     {"schema_version": 1, "manifest_sha256": sha,
                      "scope_sha256": data["scope_sha256"],
                      "budget_sha256": data["budget_sha256"],
                      "debt_sha256": digest(debt["items"]), "recorded": now(),
                      "pushes": checked, "executor_connected": False,
                      "traffic_granted": False})
    return {"validated": True, "applied": apply, "executed": False,
            "manifest_sha256": sha, "pushes": checked, "total_request_budget": total,
            "remaining_campaign_attempts": budget["remaining_campaign"],
            "notice": "No target requests, model dispatch or hourly pool enforcement. "
                      "Apply is a private review receipt, not a traffic grant or sender."}
