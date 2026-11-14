"""Per-endpoint input census: every known input name, location and source, joined
with coverage status, stored-probe receipts and the field ledger, so no field
silently goes untested.

Offline and read-only. Merges observation params (query/body/header/cookie/path
IDs per method), asset attrs and endpoint operations; never invents hidden
parameters. HAR imports capture no header/cookie names; `import-burp` closes
that gap (names only, values dropped). Each input joins its field_ledger rows
(case states) so untested ledger work is visible right in the census.
"""
from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlsplit

from .fields import FieldLedger
from .har import SENSITIVE_PARAM

INPUT_CLASSES = ("xss", "sqli", "csrf", "mass-assignment", "open-redirect",
                 "file-read", "ssrf", "idor-bola")
MAX_INPUTS = 500


def _probe_evidence(ctx, asset) -> List[Any]:
    """Stored (request_id, text) pairs whose URL query or request body may contain
    input names; body bytes are read from the on-disk body store by hash."""
    prefix = urlsplit(asset["value"]).path.split("?")[0]
    rows = ctx.store.db.execute(
        "SELECT id, url FROM requests WHERE url LIKE ?", (f"%{prefix}%",)).fetchall()
    texts: List[Any] = []
    for r in rows:
        query = (urlsplit(r["url"]).query or "").encode()
        payload = ctx.store.db.execute(
            "SELECT body_sha256 FROM request_payload WHERE request_id=?", (r["id"],)).fetchone()
        blob = b""
        if payload and payload["body_sha256"]:
            path = ctx.campaign.bodies_dir / payload["body_sha256"]
            if path.is_file():
                blob = path.read_bytes()[:200_000]
        texts.append((r["id"], query + b"\n" + blob))
    return texts


def input_census(ctx, asset_id: int) -> Dict[str, Any]:
    if type(asset_id) is not int or asset_id < 1:
        raise ValueError("asset ID must be a positive integer")
    asset = ctx.store.get_asset(asset_id)
    if asset["kind"] != "endpoint":
        raise ValueError("input census requires an endpoint asset")
    ctx.scope.check(asset["value"])
    attrs = asset.get("attrs", {})
    observations = ctx.store.observations(asset_id)
    locations: Dict[str, Dict[str, set]] = {}
    methods_by_name: Dict[str, set] = {}
    accounts: Dict[str, set] = {}
    for o in observations:
        params = o.get("params") or {}
        for bucket in ("query", "body", "header", "cookie"):
            for name in params.get(bucket) or []:
                slot = locations.setdefault(name, {})
                slot.setdefault(bucket, set()).add(o["method"])
                methods_by_name.setdefault(name, set()).add(o["method"])
                if o.get("account"):
                    accounts.setdefault(name, set()).add(o["account"])
        for name in (params.get("ids") or {}):
            slot = locations.setdefault(name, {})
            slot.setdefault("query/body (ID-like value stored)", set()).add(o["method"])
            methods_by_name.setdefault(name, set()).add(o["method"])
    for name in attrs.get("params", []):
        if name not in locations:
            locations.setdefault(name, {}).setdefault("unknown (merged attrs)", set())
            methods_by_name.setdefault(name, set())
    ids = set(attrs.get("id_params", []))
    probe_texts = _probe_evidence(ctx, asset)
    ledger = FieldLedger(ctx)
    ledger_rows: Dict[str, List[Dict[str, Any]]] = {}
    for row in ledger.db.execute(
            "SELECT field, case_id, state FROM field_ledger WHERE asset_id=? ORDER BY field",
            (asset_id,)):
        ledger_rows.setdefault(row["field"], []).append(
            {"case": row["case_id"], "state": row["state"]})
    inputs = []
    for name in sorted(locations)[:MAX_INPUTS]:
        request_ids = sorted({rid for rid, text in probe_texts
                              if name.encode() in text})
        states = ledger_rows.get(name, [])
        inputs.append({
            "name": name,
            "locations": sorted({loc for loc in locations[name]}),
            "methods": sorted(methods_by_name.get(name, set())),
            "seen_by_accounts": sorted(accounts.get(name, set())),
            "id_like": name in ids,
            "sensitive_name": bool(SENSITIVE_PARAM.search(name)),
            "probe_seen_in_requests": request_ids[:20],
            "tested": bool(request_ids),
            "ledger_states": states[:20],
            "untested_cases": len([s for s in states if s["state"] == "untested"])
            if states else None,
        })
    coverage = {row["bug_class"]: row["status"] for row in ctx.store.db.execute(
        "SELECT bug_class, status FROM coverage WHERE asset_id=?", (asset_id,)).fetchall()}
    tested_classes = {cls: status for cls, status in coverage.items()
                      if cls in INPUT_CLASSES}
    return {
        "schema_version": 1, "asset_id": asset_id, "url": asset["value"],
        "methods": sorted(attrs.get("methods", [])),
        "input_count": len(inputs), "inputs": inputs,
        "coverage": tested_classes,
        "untested_hint": sorted(cls for cls, status in tested_classes.items()
                                if status == "untested"),
        "known_gaps": ["header and cookie values are never stored; header/cookie names appear "
                       "as inputs only from Burp imports (HAR captures keep value-free CSRF "
                       "metadata instead: token channel names, cookie attributes)",
                       "hidden parameters are not guessed; add only observed or "
                       "program-documented ones"],
        "basis": "merged observations, asset attrs and stored request receipts; "
                 "probe_seen means the name appeared in a stored request, not that "
                 "a valid test was performed",
        "executed": False,
    }
