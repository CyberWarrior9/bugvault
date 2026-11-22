"""Private, offline engagement checkpoint and delta-only surface labelling.

No scope parsing, model calls, target requests, account storage or automatic run loop.
The campaign database remains the inventory and coverage source of truth. SQLite
asset-change triggers give a reliable cursor even for multiple edits in one second.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from .planning import scope_revision
from .score import AUTH_PATH, INTERNAL, UPLOAD, applicable_classes
from .skillmap import SKILLS_FOR_CLASS
from .store import now

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SIGNUP = re.compile(r"signup|sign-up|register|registration", re.I)
CONFIG = re.compile(r"(?:^|/)(?:\.env(?:\.|$)|\.git(?:/|$)|config(?:\.|/)|"
                    r"actuator(?:/|$)|debug(?:/|$)|[^/]+\.(?:bak|old|backup)$)", re.I)

EVENTS = """
CREATE TABLE IF NOT EXISTS engagement_asset_events(
  seq INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS engagement_asset_insert AFTER INSERT ON assets BEGIN
  INSERT INTO engagement_asset_events(asset_id) VALUES (new.id);
END;
CREATE TRIGGER IF NOT EXISTS engagement_asset_update AFTER UPDATE ON assets BEGIN
  INSERT INTO engagement_asset_events(asset_id) VALUES (new.id);
END;
"""


def _atomic_json(path: Path, data: dict) -> None:
    """Replace a private file atomically, never leaving a half-written checkpoint."""
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("private engagement files cannot be symlinks")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".engagement-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(data, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _load(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"missing private engagement file: {path.name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError(f"unsupported engagement file: {path.name}")
    return data


def labels(asset: dict) -> dict:
    """Source-labelled hints, not evidence that a vulnerability or render exists."""
    if asset["kind"] != "endpoint":
        return {}
    path = urlsplit(asset["value"]).path
    attrs = asset["attrs"]
    tags = {}
    if AUTH_PATH.search(path):
        tags["auth-entry"] = "path-heuristic"
    if SIGNUP.search(path):
        tags["signup"] = "path-heuristic"
    if CONFIG.search(path):
        tags["config-exposure"] = "path-heuristic"
    if attrs.get("api_like") or attrs.get("spec_fields"):
        tags["api"] = "asset-attribute"
    if UPLOAD.search(path):
        tags["upload-sink"] = "path-heuristic"
    if any(isinstance(f, dict) and f.get("location") == "multipart"
           for f in (attrs.get("spec_fields") or [])):
        tags["upload-sink"] = "declared-multipart-field"
    if INTERNAL.search(path):
        tags["internal-surface"] = "path-heuristic"
    # A path containing 'render' does not establish reflection. Tenant scoping
    # requires an actual tenant-labelled observation, not merely an ID-shaped path.
    return tags


class Engagement:
    def __init__(self, ctx, name: str):
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError("engagement id must be a 1..64 character lowercase slug")
        self.ctx = ctx
        self.path = ctx.campaign.state_dir / "engagements" / name
        if self.path.is_symlink() or self.path.parent.is_symlink() or ctx.campaign.state_dir.is_symlink():
            raise ValueError("engagement directory cannot be a symlink")
        self.checkpoint_file = self.path / "checkpoint.json"
        self.categories_file = self.path / "categories.json"
        self.debt_file = self.path / "debt.json"
        self.blocked_file = self.path / "blocked-hosts.json"

    def init(self) -> dict:
        if self.checkpoint_file.exists():
            raise ValueError("engagement already exists; use status instead")
        self.path.mkdir(parents=True, mode=0o700, exist_ok=True)
        data = {"schema_version": 1, "campaign_root": str(self.ctx.campaign.root.resolve()),
                "scope_sha256": scope_revision(self.ctx), "phase": "offline-foundation",
                "batch": 0, "created": now(), "updated": now(),
                "network_attempts_at_checkpoint": self.ctx.store.network_attempts()}
        _atomic_json(self.checkpoint_file, data)
        return data

    def checkpoint(self) -> dict:
        data = _load(self.checkpoint_file)
        if data.get("campaign_root") != str(self.ctx.campaign.root.resolve()):
            raise ValueError("checkpoint belongs to a different campaign directory")
        data["current_scope_sha256"] = scope_revision(self.ctx)
        data["scope_changed"] = data["current_scope_sha256"] != data["scope_sha256"]
        data["current_network_attempts"] = self.ctx.store.network_attempts()
        return data

    def require_current(self) -> None:
        if self.checkpoint()["scope_changed"]:
            raise ValueError("scope/policy changed since checkpoint; re-review before planning")

    def acknowledge_scope(self) -> dict:
        """Explicit offline acknowledgement, never an implicit scope expansion."""
        data = _load(self.checkpoint_file)
        if data.get("campaign_root") != str(self.ctx.campaign.root.resolve()):
            raise ValueError("checkpoint belongs to a different campaign directory")
        data["scope_sha256"] = scope_revision(self.ctx)
        data["updated"] = now()
        data["network_attempts_at_checkpoint"] = self.ctx.store.network_attempts()
        if self.categories_file.exists():
            categories = _load(self.categories_file)
            categories["force_rescan"] = True
            _atomic_json(self.categories_file, categories)
        _atomic_json(self.checkpoint_file, data)
        return self.checkpoint()

    def _phase(self, phase: str) -> None:
        data = _load(self.checkpoint_file)
        data["phase"] = phase
        data["updated"] = now()
        data["network_attempts_at_checkpoint"] = self.ctx.store.network_attempts()
        _atomic_json(self.checkpoint_file, data)

    def categorise(self) -> dict:
        self.require_current()
        self.ctx.store.db.executescript(EVENTS)
        self.ctx.store.db.commit()
        previous = _load(self.categories_file) if self.categories_file.exists() else {
            "schema_version": 1, "cursor": 0, "assets": {}}
        if not isinstance(previous.get("cursor"), int) or not isinstance(previous.get("assets"), dict):
            raise ValueError("invalid categories cursor")
        db = self.ctx.store.db
        # On first use, include all existing endpoints; later use the trigger log.
        cursor = db.execute("SELECT COALESCE(max(seq),0) FROM engagement_asset_events").fetchone()[0]
        if not self.categories_file.exists() or previous.get("force_rescan"):
            ids = [r[0] for r in db.execute("SELECT id FROM assets WHERE kind='endpoint' ORDER BY id")]
        else:
            ids = [r[0] for r in db.execute(
                "SELECT DISTINCT asset_id FROM engagement_asset_events WHERE seq>? AND seq<=? "
                "ORDER BY asset_id", (previous["cursor"], cursor))]
        assets = dict(previous["assets"])
        changes = []
        pending = dict(previous.get("pending_retags", {}))
        for aid in ids:
            a = self.ctx.store.get_asset(aid)
            key = str(aid)
            old = assets.get(key, {}).get("tags", {})
            old_classes = set(assets.get(key, {}).get("classes", []))
            tags = labels(a) if a["in_scope"] and self.ctx.scope.is_in(a["value"]) else {}
            classes = sorted(applicable_classes(a)) if tags else []
            if tags:
                assets[key] = {"tags": tags, "asset_id": aid, "value": a["value"],
                               "sources": sorted(s for s in (a["attrs"].get("sources") or [])
                                                 if isinstance(s, str))[:20],
                               "classes": classes}
            else:
                assets.pop(key, None)
            if tags != old:
                change = {"asset_id": aid, "added": sorted(set(tags) - set(old)),
                                "removed": sorted(set(old) - set(tags)),
                                "basis": {t: tags[t] for t in sorted(set(tags) - set(old))},
                                "newly_applicable_classes": sorted(set(classes) - old_classes)
                                if tags and old else []}
                changes.append(change)
                if change["newly_applicable_classes"]:
                    pending[key] = change
                elif not tags:
                    pending.pop(key, None)
        data = {"schema_version": 1, "cursor": cursor, "assets": assets,
                "last_delta": changes, "pending_retags": pending, "updated": now(),
                "note": "heuristic labels only; no target requests or finding promotion"}
        _atomic_json(self.categories_file, data)
        self._phase("categorised")
        return {"processed": len(ids), "changes": changes, "cursor": cursor,
                "total_labelled": len(assets), "executed": False}

    def blocked_hosts(self) -> dict:
        if not self.blocked_file.exists():
            return {}
        data = _load(self.blocked_file)
        if not isinstance(data.get("hosts"), dict):
            raise ValueError("invalid blocked-host record")
        return data["hosts"]

    def block_host(self, response_id: int, reason: str, note: str = "") -> dict:
        """Offline attribution of a recorded block; no retry, resume or bypass."""
        self.require_current()
        if reason not in ("429", "challenge", "lockout", "unexpected-effect", "cleanup"):
            raise ValueError("unknown block reason")
        if type(response_id) is not int or response_id < 1 or not isinstance(note, str) \
                or len(note) > 500:
            raise ValueError("block requires a stored response ID and bounded note")
        response = self.ctx.store.response(response_id)
        url = response["url"]
        if response["basis"] not in ("target-http", "imported-burp-capture", "captured-har-body"):
            raise ValueError("block receipt needs a source-labelled target response")
        if not self.ctx.scope.is_in(url):
            raise ValueError("block receipt must refer to a currently scoped target")
        if reason == "429" and response["status"] != 429:
            raise ValueError("429 blocker requires a stored 429 response")
        if reason != "429" and not note.strip():
            raise ValueError("non-429 blocks need a human-readable reason")
        host = urlsplit(url).hostname
        hosts = self.blocked_hosts()
        hosts[host] = {"reason": reason, "note": note, "request_id": response_id,
                       "recorded": now(), "source": response["basis"]}
        _atomic_json(self.blocked_file, {"schema_version": 1, "hosts": hosts})
        return {"host": host, **hosts[host], "executed": False}

    def reconcile(self) -> dict:
        """Rebuild debt from coverage, fields, exact auth cases and reachable chains."""
        from .authpolicy import AuthPolicyLedger
        from .chain import ChainLedger
        from .fields import FieldLedger, module_of

        self.categorise()
        categories = _load(self.categories_file)
        previous = _load(self.debt_file) if self.debt_file.exists() else {"schema_version": 1, "items": []}
        old = {item["id"]: item for item in previous.get("items", [])}
        checkpoint = self.checkpoint()
        blocked = self.blocked_hosts()
        items = []
        coverage = self.ctx.store.coverage()
        status_by_key = {(r["asset_id"], r["bug_class"]): r["status"] for r in coverage}
        for r in coverage:
            if r["status"] not in ("untested", "queued"):
                continue
            asset = self.ctx.store.get_asset(r["asset_id"])
            if not asset["in_scope"]:
                continue
            if asset["kind"] == "endpoint" and not self.ctx.scope.is_in(asset["value"]):
                continue
            if asset["kind"] == "service" and not any(self.ctx.scope.is_in(url) for url in
                    (asset["attrs"].get("entry_urls") or [asset["value"] + "/"])):
                continue
            if asset["kind"] in ("domain", "host") and not self.ctx.scope.host_in(asset["value"]):
                continue
            item = {"id": f"coverage:{r['asset_id']}:{r['bug_class']}",
                    "kind": "coverage", "asset_id": r["asset_id"], "class": r["bug_class"],
                    "status": r["status"], "asset_value": r["asset_value"],
                    "source": "coverage", "reason": r["reason"]}
            if r["bug_class"] not in SKILLS_FOR_CLASS:
                item["blocked_reason"] = "no routed hunt skill for this coverage class"
            elif asset["host"] in blocked:
                item["blocked_reason"] = f"host deferred: {blocked[asset['host']]['reason']}"
            items.append(item)

        endpoints = [a for a in self.ctx.store.assets("endpoint", in_scope=True)
                     if self.ctx.scope.is_in(a["value"])]
        modules = sorted({module_of(a["value"]) for a in endpoints})
        if len(modules) > 1000:
            raise ValueError("more than 1000 field modules; reconcile in bounded campaign slices")
        ledger = FieldLedger(self.ctx)
        for module in modules:
            matrix = ledger.matrix(module)
            for trigger in matrix["missing"]:
                items.append({"id": f"matrix:{module}:{trigger}", "kind": "matrix",
                              "module": module, "trigger": trigger, "source": "fields.matrix",
                               "reason": "missing captured trigger or justified n-a; not proof of a bug"})
            for expected in matrix["surface_review"]["items"]:
                if expected["state"] not in ("reviewed", "n-a"):
                    asset = self.ctx.store.get_asset(expected["asset_id"])
                    cls = ("ssti" if expected["case"] == "ssti-eval" else
                           "html-injection" if expected["case"] == "htmli-structure" else "xss")
                    item = {"id": f"surface:{expected['id']}", "kind": "surface",
                            "asset_id": expected["asset_id"], "class": cls,
                            "module": module, "surface": expected["surface"],
                            "case": expected["case"], "source": "fields.surface_matrix",
                            "reason": "declared render not independently reviewed; marker capture is not safety"}
                    if asset["host"] in blocked:
                        item["blocked_reason"] = f"host deferred: {blocked[asset['host']]['reason']}"
                    items.append(item)

        auth = AuthPolicyLedger(self.ctx)
        auth.sync()
        auth_total = auth.db.execute("SELECT count(*) FROM auth_policy_operations").fetchone()[0]
        if auth_total > 1000:
            raise ValueError("more than 1000 auth operations; reconcile in bounded campaign slices")
        auth_ops = []
        for offset in range(0, auth_total, 200):
            auth_ops.extend(auth.plan(limit=200, offset=offset)["operations"])
        for op in auth_ops:
            for case, state in op["cases"].items():
                if state in ("observed", "negative", "n-a"):
                    continue
                host = urlsplit(op["url"]).hostname
                item = {"id": f"auth-case:{op['operation_id']}:{case}", "kind": "auth-case",
                        "asset_id": op["asset_id"], "class": "security-misconfiguration",
                        "operation_id": op["operation_id"], "case": case, "status": state,
                        "endpoint": op["url"], "method": op["method"],
                        "source": "authpolicy.plan", "reason": "exact auth rule/context still needs review"}
                if host in blocked:
                    item["blocked_reason"] = f"host deferred: {blocked[host]['reason']}"
                elif op["account"] not in auth.config["owned_accounts"] or \
                        not auth.config["policy_reviewed"]:
                    item["blocked_reason"] = "owned test-account context or written-rule review not declared"
                items.append(item)

        for chain in ChainLedger(self.ctx).overview()["chains"]:
            step = chain["next"]
            # An unstarted template is a possible hunt, not an unresolved proven edge.
            if chain["state"] != "ready" or not step or not (
                    chain["proven_steps"] or step["lead_open"]):
                continue
            items.append({"id": f"chain:{chain['name']}:{step['index']}", "kind": "chain",
                          "class": step["class"], "step": step["index"],
                          "from_finding": step["lead_open"], "source": "chain.status",
                          "reason": chain["action"]})

        for change in categories.get("pending_retags", {}).values():
            aid = change["asset_id"]
            for cls in change["newly_applicable_classes"]:
                if status_by_key.get((aid, cls)) not in (None, "untested", "queued"):
                    continue
                items.append({"id": f"retag:{aid}:{cls}", "kind": "retag", "asset_id": aid,
                              "class": cls, "new_tags": change["added"],
                              "source": "categories.delta", "reason": "new heuristic tag; re-evaluate class"})

        for host, info in sorted(blocked.items()):
            items.append({"id": f"blocked-host:{host}", "kind": "blocked-host",
                          "host": host, "blocked_reason": info["reason"],
                          "request_id": info["request_id"], "source": "stored-response"})
        for item in items:
            first = old.get(item["id"], {}).get("first_batch", checkpoint["batch"])
            item["first_batch"] = first
            item["age_batches"] = max(0, checkpoint["batch"] - first)
        order = {"chain": 0, "retag": 1, "auth-case": 2, "surface": 3,
                 "coverage": 4, "matrix": 5, "blocked-host": 6}
        items.sort(key=lambda x: (bool(x.get("blocked_reason")), order[x["kind"]], x["id"]))
        data = {"schema_version": 1, "items": items, "ready": sum(
                    not i.get("blocked_reason") for i in items),
                "blocked": sum(bool(i.get("blocked_reason")) for i in items),
                "sources": ["coverage", "fields.matrix", "fields.surface_matrix",
                            "authpolicy.plan", "chain.status", "categories.delta"],
                "updated": now(), "executed": False}
        _atomic_json(self.debt_file, data)
        self._phase("debt-reconciled")
        return data
