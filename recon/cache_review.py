"""Bounded offline capture census, behavior profiles and isolation receipts.

Raw captures stay private on disk. Exports contain hashes, labels and fidelity
flags, never header values, query values or bodies. No request is executed.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import urlsplit

from .http_review import inspect_http1, split_message
from .campaign import HTTP_METHODS
from .offline_review import (MAX_ITEMS, ReviewJournal, canonical, digest, document,
                             fields, label, local)

CONTEXT = ("account", "role", "tenant", "workflow")
IDENTITY = ("behavior", "policy_revision", "path_class", "representation",
            "authority_context", "layer", "pop")
OBSERVATIONS = ("keying", "forwarding", "store", "serve", "ttl_seconds")
PURPOSES = ("isolated-observation", "owned-shared-confirmation", "control/readback")


def _headers(value):
    if not isinstance(value, list) or len(value) > 200:
        raise ValueError("capture headers must be a bounded occurrence list")
    result = []
    for header in value:
        if (not isinstance(header, dict) or not isinstance(header.get("name"), str)
                or not isinstance(header.get("value"), str)):
            raise ValueError("invalid capture header occurrence")
        result.append((header["name"].lower(), header["value"]))
    return result


def _signals(headers):
    names = [k for k, _ in headers]
    directives = {part.strip().split("=", 1)[0].lower()
                  for k, value in headers if k == "cache-control" for part in value.split(",")}
    return {"response_header_occurrences": len(names),
            "duplicate_response_headers": len(names) - len(set(names)),
            "cache_control_present": "cache-control" in names,
            "private_directive": "private" in directives,
            "no_store_directive": "no-store" in directives,
            "vary_present": "vary" in names,
            "set_cookie_present": "set-cookie" in names,
            "store": "unknown", "serve": "unknown", "layer": "unknown"}


def _har(raw):
    data = json.loads(raw)
    log = data.get("log") if isinstance(data, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list) or len(entries) > MAX_ITEMS:
        raise ValueError("HAR import needs at most 500 entries; split the capture offline")
    items = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError("HAR entries must be objects")
        req, resp = entry.get("request", {}), entry.get("response", {})
        if not isinstance(req, dict) or not isinstance(resp, dict):
            raise ValueError("HAR request/response must be objects")
        request_headers, response_headers = _headers(req.get("headers", [])), _headers(resp.get("headers", []))
        content = resp.get("content", {})
        if not isinstance(content, dict):
            raise ValueError("HAR content must be an object")
        text = content.get("text")
        body, complete = b"", False
        if isinstance(text, str):
            if content.get("encoding") == "base64":
                body = base64.b64decode(text, validate=True)
            elif content.get("encoding") in (None, ""):
                body = text.encode("utf-8")
            else:
                raise ValueError("unsupported HAR body encoding")
            complete = type(content.get("size")) is int and content["size"] == len(body)
        if len(body) > 2_000_000:
            raise ValueError("capture body exceeds two megabytes")
        items.append({"selector": index, "url": req.get("url"), "method": req.get("method"),
                      "status": resp.get("status"), "request": canonical(req).encode(),
                      "response": canonical(resp).encode(), "body": body,
                      "body_complete": complete, "fidelity": "har-normalized",
                      "request_headers": request_headers, "headers": response_headers})
    return items


def _wire(url, request, response, selector=0, complete=True):
    if not isinstance(url, str) or len(url) > 16_384:
        raise ValueError("raw capture URL must be a bounded string")
    parsed_req, parsed_resp = split_message(request), split_message(response)
    if not parsed_req or not parsed_resp:
        raise ValueError("raw capture needs complete bounded HTTP/1 header blocks")
    request_line, req_headers, _ = parsed_req
    status_line, response_headers, body = parsed_resp
    try:
        method = request_line.split(b" ")[0].decode("ascii")
        status = int(status_line.split(b" ")[1])
    except (ValueError, IndexError, UnicodeError) as exc:
        raise ValueError("invalid raw capture start line") from exc
    # Chunked/compressed bytes are not silently decoded or presented as entity bytes.
    encoded = any(name in ("transfer-encoding", "content-encoding") for name, _ in response_headers)
    request_analysis = inspect_http1(request)
    parts = urlsplit(url)
    expected = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    target_parts = request_line.split(b" ")
    if len(target_parts) != 3 or target_parts[1].decode("ascii", "replace") != expected or (
            [v.decode("ascii", "replace") for k, v in req_headers if k == "host"] != [parts.netloc]):
        request_analysis["issues"].append("capture-url-authority-or-target-mismatch")
        request_analysis["verdict"] = "reject"
    return {"selector": selector, "url": url, "method": method, "status": status,
            "request": request, "response": response, "body": body,
            "body_complete": complete and not encoded and inspect_http1(response, "response")["body_complete"],
            "fidelity": "raw-http1", "request_headers": [(k, v.decode("latin1")) for k, v in req_headers],
            "headers": [(k, v.decode("latin1")) for k, v in response_headers],
            "request_analysis": request_analysis}


class CacheReview:
    def __init__(self, ctx):
        self.ctx, self.journal = ctx, ReviewJournal(ctx, "cache")

    def import_file(self, filename, format, **context):
        if set(context) - set(CONTEXT):
            raise ValueError("unknown capture context")
        context = {k: label(context.get(k) or "unknown") for k in CONTEXT}
        raw = local(self.ctx.campaign.root, filename)
        if format == "har":
            items = _har(raw)
        elif format in ("burp-xml", "burp-json"):
            from .burp import _json_items, _xml_items
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise ValueError("XML declarations/entities are not accepted")
            parsed = _xml_items(raw) if format == "burp-xml" else _json_items(raw)
            if len(parsed) > MAX_ITEMS:
                raise ValueError("Burp capture import exceeds 500 entries")
            items = [_wire(item.url, item.request_bytes, item.response_bytes, i,
                           complete=not (item.request_truncated or item.response_truncated))
                     for i, item in enumerate(parsed) if item.request_bytes and item.response_bytes]
            if len(items) != len(parsed):
                raise ValueError("every Burp item needs both request and response")
        elif format == "raw-pair":
            manifest = json.loads(raw)
            fields(manifest, ("schema", "url", "request", "response"))
            if type(manifest["schema"]) is not int or manifest["schema"] != 1:
                raise ValueError("raw pair needs schema 1")
            items = [_wire(manifest["url"], local(self.ctx.campaign.root, manifest["request"]),
                           local(self.ctx.campaign.root, manifest["response"]))]
            items[0].update(request_source=manifest["request"], response_source=manifest["response"])
        else:
            raise ValueError("unknown cache capture format")
        # Validate every entry before committing rows; no partially imported envelope.
        total = len(raw)
        for item in items:
            if not isinstance(item["url"], str) or len(item["url"]) > 16_384:
                raise ValueError("capture URL must be a bounded string")
            parts = urlsplit(item["url"] or "")
            if parts.scheme not in ("http", "https") or not self.ctx.scope.is_in(item["url"]):
                raise ValueError("capture URL is outside campaign scope")
            if not isinstance(item["method"], str) or item["method"] not in HTTP_METHODS:
                raise ValueError("capture method is invalid")
            if type(item["status"]) is not int or not 100 <= item["status"] <= 599:
                raise ValueError("capture status is invalid")
            total += sum(len(item[k]) for k in ("request", "response", "body"))
            if any(len(item[k]) > 5_000_000 for k in ("request", "response", "body")):
                raise ValueError("capture component exceeds five megabytes")
        if total > 25_000_000:
            raise ValueError("capture envelope exceeds 25 megabytes")
        source = self.journal.artifact(filename)
        ids = []
        with self.ctx.store.db:
            for item in items:
                parts = urlsplit(item["url"])
                artifacts = {"source": source, **{k: self.journal.retain(
                             item[k], source=item.get(k + "_source"))
                             for k in ("request", "response", "body")}}
                snapshot = {"origin": f"{parts.scheme}://{parts.netloc}", "method": item["method"],
                            "status": item["status"], "url_sha256": digest(item["url"].encode()),
                            "selector": item["selector"], "source_kind": format,
                            "fidelity": item["fidelity"], "body_complete": item["body_complete"],
                            "request_analysis": item.get("request_analysis", {"verdict": "unavailable-normalized-capture"}),
                            "context": context, "signals": _signals(item["headers"]),
                            "authority_present": any(k in ("authorization", "cookie")
                                                     for k, _ in item["request_headers"]),
                            "artifacts": artifacts}
                ids.append(self.journal.append("capture", snapshot, commit=False))
        return {"captures": ids, "source_kind": format, "executed": False,
                "finding_promoted": False, "cache_semantics_verified": False}

    def profile(self, filename):
        data = document(self.ctx.campaign.root, filename)
        fields(data, ("schema", "capture", "identity", "observations", "evidence"))
        if type(data["schema"]) is not int or data["schema"] != 1:
            raise ValueError("profile needs schema 1")
        row, capture = self.journal.get(data["capture"], "capture")
        if self.journal.verify_one(row, capture):
            raise ValueError("capture is stale or invalid")
        fields(data["identity"], IDENTITY)
        identity = {k: label(data["identity"][k]) for k in IDENTITY}
        fields(data["observations"], OBSERVATIONS)
        obs = data["observations"]
        if obs["keying"] not in ("unknown", "keyed", "unkeyed", "transformed"):
            raise ValueError("unknown keying observation")
        if any(obs[k] not in ("unknown", "yes", "no") for k in ("forwarding", "store", "serve")):
            raise ValueError("profile facets need explicit unknown/yes/no")
        if obs["ttl_seconds"] is not None and (type(obs["ttl_seconds"]) is not int or
                                                not 0 <= obs["ttl_seconds"] <= 31_536_000):
            raise ValueError("TTL is unknown (null) or a bounded integer")
        # Unknowns are never wildcard joins; profiles stay capture/context scoped.
        snapshot = {"capture": data["capture"], "capture_hash": row["sha256"],
                    "origin": capture["origin"], "method": capture["method"],
                    "response_status": capture["status"],
                    "context": capture["context"], "identity": identity, "observations": obs,
                    "semantic_review_required": True,
                    "artifacts": {"declaration": self.journal.artifact(filename),
                                  "evidence": self.journal.artifact(data["evidence"])}}
        return {"id": self.journal.append("profile", snapshot), "executed": False,
                "semantic_review_required": True, "finding_promoted": False}

    def isolation(self, filename):
        data = document(self.ctx.campaign.root, filename)
        fields(data, ("schema", "profile", "purpose", "state", "viewer", "artifacts"),
               ("attempt", "partition_sha256", "cleanup_owner"))
        if type(data["schema"]) is not int or data["schema"] != 1:
            raise ValueError("isolation receipt needs schema 1")
        row, profile = self.journal.get(data["profile"], "profile")
        if self._integrity(row, profile):
            raise ValueError("profile is stale or invalid")
        if data["purpose"] not in PURPOSES or data["state"] not in ("unknown", "source-supported", "contradicted"):
            raise ValueError("unknown isolation purpose/state")
        label(data["viewer"])
        attempt = label(data.get("attempt", "unknown"))
        cleanup_owner = label(data.get("cleanup_owner", "unknown"))
        partition = data.get("partition_sha256")
        if partition is not None and (not isinstance(partition, str) or len(partition) != 64 or
                                      any(c not in "0123456789abcdef" for c in partition)):
            raise ValueError("partition identity must be a lowercase SHA-256 or null")
        fields(data["artifacts"], (), ("partition", "control", "cleanup"))
        receipts = {k: self.journal.artifact(v) for k, v in data["artifacts"].items()}
        if data["state"] == "source-supported":
            if not {"partition", "control"} <= receipts.keys() or (
                    receipts["partition"]["sha256"] == receipts["control"]["sha256"]):
                raise ValueError("isolation support needs distinct partition/control evidence")
        snapshot = {k: data[k] for k in ("profile", "purpose", "state", "viewer")}
        snapshot.update({"profile_hash": row["sha256"], "artifacts": receipts,
                         "attempt": attempt, "partition_sha256": partition,
                         "cleanup_owner": cleanup_owner,
                         "semantic_review_required": True})
        return {"id": self.journal.append("isolation", snapshot), "executed": False,
                "traffic_authorized": False, "semantic_review_required": True,
                "finding_promoted": False}

    def show(self, record_id):
        row, data = self.journal.get(record_id)
        # Raw sources/paths and all header/body values remain local, not in reports.
        visible = {k: v for k, v in data.items() if k not in ("artifacts", "policy_hash")}
        return {"id": record_id, "kind": row["kind"], **visible,
                "artifact_hashes": {k: v["sha256"] for k, v in data["artifacts"].items()},
                "integrity_issues": self._integrity(row, data), "executed": False,
                "cache_semantics_verified": False, "finding_promoted": False}

    def status(self, kind=None, limit=100, offset=0):
        if kind not in (None, "capture", "profile", "isolation"):
            raise ValueError("unknown cache review record kind")
        rows, page = self.journal.page(kind, limit, offset)
        return {**page, "rows": [self.show(row["id"]) for row in rows],
                "executed": False, "finding_promoted": False}

    def verify(self, limit=100, offset=0):
        result = self.journal.verify(limit, offset)
        rows, _ = self.journal.page(limit=limit, offset=offset)
        for row in rows:
            try:
                _, data = self.journal.get(row["id"])
                if self._integrity(row, data):
                    raise ValueError("dependent capture/profile stale or invalid")
            except (ValueError, TypeError, KeyError):
                result["issues"].append({"id": row["id"], "reason": "review dependency invalid"})
        result["ok"] = not result["issues"]
        result["cache_semantics_verified"] = False
        return result

    def _integrity(self, row, data, depth=0):
        issues = self.journal.verify_one(row, data)
        if depth > 2:
            return issues + ["review dependency depth exceeded"]
        for key, kind in (("capture", "capture"), ("profile", "profile")):
            if key not in data:
                continue
            try:
                parent, snapshot = self.journal.get(data[key], kind)
                if parent["sha256"] != data[key + "_hash"] or self._integrity(parent, snapshot, depth + 1):
                    raise ValueError("review dependency invalid")
            except (ValueError, TypeError, KeyError):
                issues.append("dependent " + key + " invalid/stale")
        return issues
