"""Deterministic, response-backed predicates, not semantic vulnerability verdicts.

Legacy narrative facts remain unchecked. These typed facts have code-generated
claims, a concrete request ID and a response snapshot; arbitrary prose cannot be
smuggled into a verified status/header/byte predicate. Verification is entirely offline.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from .campaign import PolicyViolation, norm_host
from .extract import endpoint_key, origin_of
from .store import now

CHECKER_VERSION = "response-predicates-v1"
MAX_BODY_BYTES = 5_000_000
FIELDS = {"status_is": {"type", "expected"}, "header_present": {"type", "name"},
          "header_equals": {"type", "name", "expected"}, "body_contains_raw": {"type", "marker"}}


def _encode(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def response_hash(response):
    return hashlib.sha256(_encode(response).encode()).hexdigest()


def validate_predicate(predicate: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(predicate, dict) or not isinstance(predicate.get("type"), str):
        raise ValueError("predicate must be an object with a supported type")
    kind = predicate["type"]
    if kind not in FIELDS or set(predicate) != FIELDS[kind]:
        raise ValueError("unsupported predicate or unexpected fields; free-form claims are not accepted")
    out = dict(predicate)
    if kind == "status_is":
        if type(out["expected"]) is not int or not 100 <= out["expected"] <= 599:
            raise ValueError("expected HTTP status must be an integer from 100 to 599")
    if kind.startswith("header_"):
        name = out["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", name):
            raise ValueError("invalid HTTP header name")
        out["name"] = name.lower()
    if kind == "header_equals":
        if not isinstance(out["expected"], str) or len(out["expected"]) > 4096 or any(
                c in out["expected"] for c in "\r\n\x00"):
            raise ValueError("expected header value must be a bounded single-line string")
    if kind == "body_contains_raw":
        marker = out["marker"]
        if not isinstance(marker, str) or not 1 <= len(marker.encode("utf-8")) <= 1024:
            raise ValueError("marker must contain 1..1024 UTF-8 bytes")
    return out


class ResponseFacts:
    def __init__(self, ctx):
        self.ctx, self.store, self.db = ctx, ctx.store, ctx.store.db

    def _binding(self, response, asset_id):
        if not self.ctx.campaign.scope.is_in(response["url"]):
            raise PolicyViolation("response facts must refer to a currently in-scope target response")
        if asset_id is None:
            return
        asset = self.store.get_asset(asset_id)
        if asset["kind"] == "endpoint":
            same = endpoint_key(asset["value"]) == endpoint_key(response["url"])
        elif asset["kind"] == "service":
            same = origin_of(asset["value"]) == origin_of(response["url"])
        elif asset["kind"] in ("js", "sourcemap", "route"):
            same = (origin_of(asset["value"]), urlsplit(asset["value"]).path) == (
                origin_of(response["url"]), urlsplit(response["url"]).path)
        elif asset["kind"] in ("host", "domain", "ip"):
            same = norm_host(asset["value"]) == norm_host(urlsplit(response["url"]).hostname or "")
        else:
            same = False
        if not same:
            raise ValueError("stored response does not belong to the selected asset")

    def add(self, request_id: int, predicate: Dict[str, Any], asset_id: Optional[int] = None):
        if type(request_id) is not int or request_id < 1 or (asset_id is not None and (
                type(asset_id) is not int or asset_id < 1)):
            raise ValueError("request/asset IDs must be positive integers")
        predicate = validate_predicate(predicate)
        response = self.store.response(request_id)
        self._binding(response, asset_id)
        encoded = _encode(predicate)
        snapshot = response_hash(response)
        binding = f"asset:{asset_id}" if asset_id is not None else "response-only"
        self.db.execute("INSERT OR IGNORE INTO response_facts(request_id,asset_id,binding_key,predicate,"
                        "response_sha256,created) VALUES(?,?,?,?,?,?)",
                        (request_id, asset_id, binding, encoded, snapshot, now()))
        row = self.db.execute("SELECT id FROM response_facts WHERE request_id=? AND binding_key=? "
                              "AND predicate=? AND response_sha256=?", (request_id, binding, encoded, snapshot)).fetchone()
        self.db.commit()
        return self.verify(row["id"])

    def verify(self, fact_id: int, *, persist: bool = True):
        row = self.db.execute("SELECT * FROM response_facts WHERE id=?", (fact_id,)).fetchone()
        if row is None:
            raise KeyError(f"no response-backed fact {fact_id}")
        predicate = validate_predicate(json.loads(row["predicate"]))
        detail: Dict[str, Any] = {}
        try:
            response = self.store.response(row["request_id"])
        except (ValueError, KeyError, TypeError):
            response = None
            outcome, reason = "inconclusive", "response_record_unavailable_or_invalid"
        else:
            try:
                self._binding(response, row["asset_id"])
            except (PolicyViolation, ValueError, KeyError):
                outcome, reason = "stale", "scope_or_asset_binding_changed"
            else:
                if response_hash(response) != row["response_sha256"]:
                    outcome, reason = "stale", "response_snapshot_changed"
                elif response["error"] or type(response["status"]) is not int or not 100 <= response["status"] <= 599:
                    outcome, reason = "inconclusive", "no_usable_http_response"
                else:
                    outcome, reason, detail = self._evaluate(response, predicate)
        result = {"fact_id": fact_id, "request_id": row["request_id"], "asset_id": row["asset_id"],
                  "url": response["url"] if response else None,
                  "method": response["method"] if response else None,
                  "context": response["context"] if response else {},
                  "captured_at": response["ts"] if response else None,
                  "predicate": predicate, "claim": self._claim(predicate, row["request_id"]),
                  "outcome": outcome, "reason": reason, "detail": detail,
                  "response_sha256": row["response_sha256"],
                  "capture_basis": response["basis"] if response else "unknown",
                  "checker_version": CHECKER_VERSION}
        if persist:
            cur = self.db.execute("INSERT INTO fact_verifications(fact_id,outcome,checker_version,detail,checked) "
                                  "VALUES(?,?,?,?,?)", (fact_id, outcome, CHECKER_VERSION,
                                                        _encode({"reason": reason, **detail,
                                                                 "response_sha256": row["response_sha256"],
                                                                 "predicate_sha256": hashlib.sha256(_encode(predicate).encode()).hexdigest()}), now()))
            self.db.commit()
            result["verification_id"] = cur.lastrowid
        return result

    def recent(self, limit: int = 50):
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("fact list limit must be 1..200")
        ids = [r[0] for r in self.db.execute("SELECT id FROM response_facts ORDER BY id DESC LIMIT ?", (limit,))]
        return [self.verify(fid, persist=False) for fid in ids]

    def require_supported(self, fact_ids):
        """Export only freshly rechecked predicates, not arbitrary narrative claims.

        This is a building block for the future context gate, not an LLM invocation.
        Model-sharing/redaction policy and hypothesis-specific requirements remain separate.
        """
        if (not isinstance(fact_ids, list) or not 1 <= len(fact_ids) <= 20
                or any(type(fid) is not int or fid < 1 for fid in fact_ids)
                or len(set(fact_ids)) != len(fact_ids)):
            raise ValueError("context export requires 1..20 distinct positive fact IDs")
        facts = [self.verify(fid) for fid in fact_ids]
        unsupported = [f"{f['fact_id']}={f['outcome']}" for f in facts if f["outcome"] != "supported"]
        if unsupported:
            raise ValueError("context facts are not supported: " + ", ".join(unsupported))
        return {"schema_version": 1, "response_facts": facts,
                "notice": "Only the listed predicates are supported by stored records. No vulnerability "
                          "conclusion, live re-test, model call or data-sharing approval is implied."}

    @staticmethod
    def _claim(predicate, request_id):
        kind = predicate["type"]
        if kind == "status_is":
            text = f"Recorded status equals {predicate['expected']}"
        elif kind == "header_present":
            text = f"Recorded header {predicate['name']} is present"
        elif kind == "header_equals":
            value_hash = hashlib.sha256(predicate["expected"].encode()).hexdigest()
            text = f"Recorded header {predicate['name']} has the specified exact value (SHA-256 {value_hash})"
        else:
            marker_hash = hashlib.sha256(predicate["marker"].encode()).hexdigest()
            text = f"Captured body contains the exact UTF-8 sequence (SHA-256 {marker_hash}), without decoding"
        return f"{text}; response #{request_id}"

    def _evaluate(self, response, predicate):
        kind = predicate["type"]
        if kind == "status_is":
            matches = response["status"] == predicate["expected"]
            return ("supported" if matches else "contradicted", "status_compared", {"actual_status": response["status"]})
        headers = response["resp_headers"]
        if not isinstance(headers, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                                for k, v in headers.items()):
            return "inconclusive", "invalid_recorded_headers", {}
        if kind.startswith("header_"):
            values = [value for name, value in headers.items() if name.lower() == predicate["name"]]
            matches = bool(values) if kind == "header_present" else predicate["expected"] in values
            return "supported" if matches else "contradicted", "recorded_headers_compared", {"recorded_occurrences": len(values)}
        encoding = next((v.strip().lower() for k, v in headers.items() if k.lower() == "content-encoding"), "identity")
        if encoding not in ("", "identity"):
            return "inconclusive", "content_encoding_not_supported", {}
        size, sha = response["body_len"], response["body_sha256"]
        if type(size) is not int or size < 0 or size > MAX_BODY_BYTES:
            return "inconclusive", "body_size_invalid_or_over_verification_limit", {}
        if size == 0 and sha is None:
            body = b""
        else:
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                return "inconclusive", "missing_or_invalid_body_hash", {}
            path = self.store.bodies_dir / sha
            try:
                with path.open("rb") as source:
                    body = source.read(MAX_BODY_BYTES + 1)
            except OSError:
                return "inconclusive", "body_unavailable", {}
            if len(body) != size or hashlib.sha256(body).hexdigest() != sha:
                return "inconclusive", "body_integrity_failed", {}
        marker = predicate["marker"].encode("utf-8")
        offset = body.find(marker)
        if offset >= 0:
            return "supported", "exact_raw_bytes_found", {"byte_offset": offset, "marker_bytes": len(marker)}
        if response["body_complete"] != 1:
            return "inconclusive", "marker_absent_from_incomplete_or_unknown_capture", {}
        return "contradicted", "marker_absent_from_complete_capture", {}
