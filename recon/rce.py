"""Offline source-qualified RCE candidate and evidence review; never executes code.

All operator documents and artifacts are campaign-local, treated as untrusted data,
hash-bound and kept private. 'Qualified' means an explicit *source-supported* sink
path exists for an exact endpoint; it is not server behavior or a finding.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from . import cmdi, deser
from .callbacks import valid_marker
from .campaign import HTTP_METHODS
from .execproof import CHANNELS, STATES, assess
from .extract import endpoint_key
from .offline_review import ReviewJournal, digest, document, fields, label, local

FAMILIES = {cmdi.FAMILY: cmdi, deser.FAMILY: deser}
LOCATIONS = frozenset({"path", "query", "body", "header", "cookie", "file", "message"})
STAGES = frozenset({"entry", "decode", "transform", "store", "queue", "worker", "sink"})
BASES = frozenset({"capture", "authorized-source", "owner-log", "owned-lab"})
TIERS = frozenset({"review-only", "owned-lab", "potential-supervised"})
ROLES = frozenset({"baseline", "trigger", "replay-request", "verification", "negative-control",
                   "positive-control", "effect", "worker-log", "worker-replay", "cleanup", "impact"})
CONTEXT = ("account", "role", "tenant", "workflow")
ROUTE_SOURCES = frozenset({"har", "burp", "authorized-source", "owner-log", "owned-lab"})
TIMES = frozenset({"baseline", "trigger", "replay", "negative", "cleanup"})
FIDELITY = frozenset({"effect", "verification", "baseline", "negative-control",
                      "positive-control"})


class RceLedger:
    def __init__(self, ctx):
        self.ctx, self.journal = ctx, ReviewJournal(ctx, "rce")

    def _asset(self, asset_id, url):
        if asset_id is None:
            return None
        if type(asset_id) is not int or asset_id <= 0:
            raise ValueError("asset_id must be an existing positive endpoint ID")
        asset = self.ctx.store.get_asset(asset_id)
        if (asset["kind"] != "endpoint" or not asset["in_scope"] or
                not self.ctx.scope.is_in(asset["value"]) or
                endpoint_key(asset["value"]) != endpoint_key(url)):
            raise ValueError("RCE sink needs an in-scope endpoint asset for this exact route")
        return asset

    def _qualified(self, data):
        asset = self._asset(data.get("asset_id"), data["url"])
        edges = data["edges"]
        if not asset:
            return False
        source_names = asset["attrs"].get("sources", [])
        if (not isinstance(source_names, list) or not all(isinstance(s, str) for s in source_names)
                or not (set(source_names) & ROUTE_SOURCES)):
            return False  # a JS-only/client-side or inferred route is a lead
        raw_methods = asset["attrs"].get("methods") or []
        if not isinstance(raw_methods, list) or not all(isinstance(m, str) for m in raw_methods):
            return False
        methods = set(raw_methods)
        if methods and data["method"] not in methods:
            return False
        op = self.ctx.store.db.execute(
            "SELECT attrs FROM endpoint_operations WHERE endpoint_id=? AND method=?",
            (asset["id"], data["method"])).fetchone()
        if op:
            op_sources = json.loads(op["attrs"]).get("sources", [])
            if (not isinstance(op_sources, list) or not all(isinstance(s, str) for s in op_sources)
                    or not (set(op_sources) & ROUTE_SOURCES)):
                return False  # a different method's capture does not qualify this operation
        elif self.ctx.store.db.execute(
                "SELECT 1 FROM endpoint_operations WHERE endpoint_id=? LIMIT 1",
                (asset["id"],)).fetchone():
            return False
        path = urlsplit(data["url"]).path or "/"
        variants = self.ctx.store.db.execute(
            "SELECT method,path FROM endpoint_variants WHERE endpoint_id=?", (asset["id"],)).fetchall()
        if variants:
            if not any(v["method"] == data["method"] and v["path"] == path for v in variants):
                return False
        elif (urlsplit(asset["value"]).path or "/") != path:
            return False
        receipts = data.get("artifacts", {})
        if any(receipts.get("edge-%02d" % i, {}).get("bytes", 0) < 1
               for i in range(len(edges))):
            return False
        return bool(data["consumer"] != "unknown" and edges[0]["stage"] == "entry" and
                    edges[-1]["stage"] == "sink" and
                    all(edge["certainty"] == "direct" for edge in edges) and
                    all(edge["stage"] not in ("entry", "sink") for edge in edges[1:-1]) and
                    edges[-1]["basis"] in ("authorized-source", "owner-log", "owned-lab"))

    def declare(self, relative):
        spec = document(self.ctx.campaign.root, relative)
        fields(spec, ("schema", "family", "url", "method", "field", "location", "context",
                      "consumer", "sink_kind", "runtime", "edges"), ("asset_id", "tier"))
        if type(spec["schema"]) is not int or spec["schema"] != 1:
            raise ValueError("RCE sink needs schema 1")
        family = spec["family"]
        if not isinstance(family, str) or family not in FAMILIES:
            raise ValueError("unknown RCE candidate family")
        FAMILIES[family].validate_sink(spec["sink_kind"])
        url = spec["url"]
        if not isinstance(url, str) or len(url) > 4096:
            raise ValueError("RCE route needs a bounded URL")
        parts = urlsplit(url)
        if (parts.scheme not in ("http", "https") or parts.username is not None or
                parts.password is not None or parts.fragment or not self.ctx.scope.is_in(url)):
            raise ValueError("RCE route must be an exact in-scope HTTP(S) URL")
        if (not isinstance(spec["method"], str) or spec["method"] not in HTTP_METHODS or
                not isinstance(spec["location"], str) or spec["location"] not in LOCATIONS):
            raise ValueError("RCE route needs a supported method and input location")
        for key in ("field", "consumer", "runtime"):
            label(spec[key])
        fields(spec["context"], CONTEXT)
        context = {key: label(spec["context"][key]) for key in CONTEXT}
        tier = spec.get("tier", "review-only")
        if not isinstance(tier, str) or tier not in TIERS:
            raise ValueError("RCE tier is an evidence label, not a traffic grant")
        edges = spec["edges"]
        if not isinstance(edges, list) or not 2 <= len(edges) <= 12:
            raise ValueError("RCE source graph needs 2..12 ordered edges")
        normalized = []
        for edge in edges:
            fields(edge, ("stage", "basis", "certainty", "reference", "artifact"))
            if (not all(isinstance(edge[key], str) for key in
                        ("stage", "basis", "certainty")) or edge["stage"] not in STAGES or
                    edge["basis"] not in BASES or
                    edge["certainty"] not in ("direct", "inferred", "unknown")):
                raise ValueError("unknown source graph stage, basis or certainty")
            normalized.append({k: edge[k] for k in ("stage", "basis", "certainty", "reference")})
            label(edge["reference"])
        if normalized[0]["stage"] != "entry" or normalized[-1]["stage"] != "sink":
            raise ValueError("RCE graph must start at entry and finish at a sink")
        asset = self._asset(spec.get("asset_id"), url)
        data = {"family": family, "url": url, "url_sha256": digest(url.encode()),
                "origin": f"{parts.scheme}://{parts.netloc}", "method": spec["method"],
                "asset_id": asset["id"] if asset else None, "field": spec["field"],
                "location": spec["location"], "context": context, "consumer": spec["consumer"],
                "sink_kind": spec["sink_kind"], "runtime": spec["runtime"],
                "tier": tier, "edges": normalized}
        data["artifacts"] = {"declaration": self.journal.artifact(relative),
                             **{"edge-%02d" % i: self.journal.artifact(edge["artifact"])
                                for i, edge in enumerate(edges)}}
        qualified = self._qualified(data)
        data["qualified"] = qualified
        record_id = self.journal.append("sink", data)
        inserted = 0
        if qualified:
            inserted = self.ctx.store.seed_coverage(asset["id"], {family:
                "operator-supplied source-qualified sink path; execution and sink semantics unverified"})
        return {"id": record_id, "family": family, "source_supported": qualified,
                "coverage_seeded": bool(inserted), "traffic_authorized": False,
                "executed": False, "finding_promoted": False}

    def record(self, relative):
        spec = document(self.ctx.campaign.root, relative)
        fields(spec, ("schema", "sink", "state", "channel", "effect_channel", "artifacts"),
               ("markers", "fidelity", "times", "binding", "note"))
        if type(spec["schema"]) is not int or spec["schema"] != 1:
            raise ValueError("RCE receipt needs schema 1")
        row, sink = self.journal.get(spec["sink"], "sink")
        if self._integrity(row, sink):
            raise ValueError("RCE sink evidence is stale or invalid")
        # `live-target` accepted with D4: a live receipt meets the same eight roles,
        # three distinct markers, identity-encoded captures and ordered times as a lab
        # one. The channel no longer decides, the evidence does.
        if (not all(isinstance(spec[key], str) for key in ("state", "channel", "effect_channel")) or
                spec["state"] not in STATES or
                spec["channel"] not in ("offline", "owned-lab", "live-target") or
                spec["effect_channel"] not in CHANNELS):
            raise ValueError("RCE receipt channel must be offline, owned-lab or live-target, "
                             "with a known state and effect channel")
        files = spec["artifacts"]
        if not isinstance(files, dict) or set(files) - ROLES or len(files) > len(ROLES):
            raise ValueError("RCE evidence roles must be bounded known names")
        if "note" in spec:
            label(spec["note"])
        markers = spec.get("markers", {})
        if not isinstance(markers, dict) or set(markers) - {"effect", "replay", "control"} or (
                any(not valid_marker(m) for m in markers.values())):
            raise ValueError("RCE markers must be bounded owned labels")
        if not isinstance(spec.get("fidelity", {}), dict) or (
                set(spec.get("fidelity", {})) - FIDELITY):
            raise ValueError("RCE fidelity must use known evidence roles")
        for item in spec.get("fidelity", {}).values():
            fields(item, ("complete", "encoding"))
            if type(item["complete"]) is not bool or not isinstance(item["encoding"], str) or (
                    len(item["encoding"]) > 32):
                raise ValueError("RCE fidelity values must be bounded capture descriptors")
        times = spec.get("times", {})
        fields(times, (), TIMES)
        from .callbacks import timestamp
        for value in times.values():
            if not isinstance(value, str) or len(value) > 64:
                raise ValueError("RCE attempt time is not a bounded ISO timestamp")
            timestamp(value)
        binding = spec.get("binding", {})
        if binding:
            fields(binding, (*CONTEXT, "consumer", "owned_object"))
            for key, value in binding.items():
                label(value)
            if any(binding[key] != sink["context"][key] for key in CONTEXT) or (
                    binding["consumer"] != sink["consumer"]):
                raise ValueError("RCE receipt actor/worker must match the declared sink")
        elif not isinstance(binding, dict):
            raise ValueError("RCE receipt binding must be an object")
        receipts = {key: self.journal.artifact(value) for key, value in files.items()}
        contents = {key: local(self.ctx.campaign.root, value) for key, value in files.items()}
        result = assess({**spec, "binding": binding}, contents, sink["qualified"])
        snapshot = {"sink": row["id"], "sink_hash": row["sha256"],
                    "family": sink["family"], "origin": sink["origin"], "method": sink["method"],
                    "state": spec["state"], "channel": spec["channel"],
                    "effect_channel": spec["effect_channel"], "markers": markers,
                    "fidelity": spec.get("fidelity", {}), "times": times, "binding": binding,
                    "note": spec.get("note", "unknown"), "assessment": result,
                    "artifacts": {"declaration": self.journal.artifact(relative), **receipts}}
        record_id = self.journal.append("receipt", snapshot)
        return {"id": record_id, **result, "executed": False, "finding_promoted": False}

    def _integrity(self, row, data):
        try:
            issues = self.journal.verify_one(row, data)
        except (ValueError, KeyError, TypeError, AttributeError):
            return ["invalid RCE review snapshot"]
        try:
            if row["kind"] == "sink":
                if not self.ctx.scope.is_in(data["url"]) or digest(data["url"].encode()) != data["url_sha256"]:
                    raise ValueError("sink scope or URL digest changed")
                if data["qualified"] != self._qualified(data):
                    raise ValueError("sink qualification is stale")
            elif row["kind"] == "receipt":
                parent, sink = self.journal.get(data["sink"], "sink")
                if data["sink_hash"] != parent["sha256"] or self._integrity(parent, sink):
                    raise ValueError("sink dependency invalid")
                files = {key: local(self.ctx.campaign.root, receipt["path"])
                         for key, receipt in data["artifacts"].items() if key != "declaration"}
                claim = {key: data[key] for key in ("state", "channel", "effect_channel", "markers",
                                                    "fidelity", "times", "binding")}
                if assess(claim, files, sink["qualified"]) != data["assessment"]:
                    raise ValueError("evidence assessment changed")
            else:
                raise ValueError("unknown RCE journal kind")
        except (ValueError, KeyError, TypeError, OSError, AttributeError, IndexError):
            issues.append("RCE dependency or snapshot invalid")
        return issues

    def show(self, record_id):
        try:
            row, data = self.journal.get(record_id)
        except ValueError:
            if type(record_id) is not int or record_id < 1:
                raise
            row = self.ctx.store.db.execute(
                "SELECT id,kind FROM offline_reviews WHERE id=? AND domain='rce'",
                (record_id,)).fetchone()
            if row is None:
                raise
            return {"id": record_id, "kind": row["kind"], "family": "unknown",
                    "origin": "unknown", "artifact_hashes": {},
                    "integrity_issues": ["invalid RCE review snapshot"],
                    "traffic_authorized": False, "executed": False, "finding_promoted": False}
        try:
            safe = {k: data[k] for k in (("family", "origin", "method", "location",
                                         "sink_kind", "tier", "asset_id", "qualified", "url_sha256")
                                        if row["kind"] == "sink" else
                                        ("family", "origin", "method", "sink", "state", "channel",
                                         "effect_channel", "assessment")) if k in data}
            if row["kind"] == "sink":
                safe["label_hashes"] = {key: digest(value.encode())[:16] for key, value in
                                        {"field": data["field"], "consumer": data["consumer"],
                                         **data["context"]}.items()}
                safe["edge_count"] = len(data["edges"])
            artifacts = {key: value["sha256"] for key, value in data["artifacts"].items()}
        except (ValueError, KeyError, TypeError, AttributeError):
            safe, artifacts = {"family": "unknown", "origin": "unknown"}, {}
        return {"id": record_id, "kind": row["kind"], **safe,
                "artifact_hashes": artifacts, "integrity_issues": self._integrity(row, data),
                "traffic_authorized": False, "executed": False, "finding_promoted": False}

    def status(self, limit=50, offset=0):
        rows, page = self.journal.page(limit=limit, offset=offset)
        return {**page, "rows": [self.show(row["id"]) for row in rows],
                "coverage_complete": False, "executed": False, "finding_promoted": False}

    def verify(self, limit=100, offset=0):
        result = self.journal.verify(limit=limit, offset=offset)
        rows, _ = self.journal.page(limit=limit, offset=offset)
        for row in rows:
            try:
                issues = self._integrity(row, self.journal.get(row["id"])[1])
            except (ValueError, KeyError, TypeError):
                issues = ["invalid RCE journal entry"]
            result["issues"].extend({"id": row["id"], "reason": issue} for issue in issues
                                    if {"id": row["id"], "reason": issue} not in result["issues"])
        result["ok"] = not result["issues"]
        result.update(coverage_complete=False, execution_verified=False)
        return result
