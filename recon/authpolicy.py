"""Offline exact-operation auth-policy inventory and evidence review.

No password attempts, token replay, model calls, target traffic or finding promotion.
All reported observations are operator-labelled leads, not security verdicts.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .campaign import HTTP_METHODS, validate_auth_policy
from .extract import endpoint_key
from .factcheck import response_hash
from .offline_review import ReviewJournal, label, local
from .score import AUTH_PATH
from .store import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_policy_operations(
  id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
  url TEXT NOT NULL, method TEXT NOT NULL, entry_point TEXT NOT NULL,
  account TEXT NOT NULL, role TEXT NOT NULL, tenant TEXT NOT NULL,
  workflow TEXT NOT NULL, representation TEXT NOT NULL,
  source TEXT NOT NULL, source_ref TEXT NOT NULL, created TEXT NOT NULL,
  UNIQUE(asset_id,url,method,entry_point,account,role,tenant,workflow,representation));
CREATE TABLE IF NOT EXISTS auth_policy_case_events(
  id INTEGER PRIMARY KEY, operation_id INTEGER NOT NULL REFERENCES auth_policy_operations(id),
  case_id TEXT NOT NULL, review_id INTEGER NOT NULL REFERENCES offline_reviews(id),
  created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS auth_policy_case_operation ON auth_policy_case_events(operation_id,case_id,id);
"""

ENTRY_CASES = {
    "signup": ("password-constraint",),
    "password-change": ("password-constraint", "change-sessions", "change-reset-links"),
    "password-reset": ("password-constraint",),
    "invite": ("password-constraint",),
    "admin-set": ("password-constraint",),
    "oauth-local": ("password-constraint",),
    "recovery": ("password-constraint",),
    "api-direct": ("password-constraint",),
    "email-change": ("email-change-old-links",),
    "logout": ("logout-session",),
    "logout-all": ("logout-all-sessions",),
    "mfa-change": ("mfa-change-sessions",),
    "login": ("login-rate-limit",),
    "forgot-request": ("reset-request-rate-limit",),
    "session": (),
    "token-reference": ("token-derivation",),
}
WRITE_ONLY = {"password-constraint", "change-sessions", "change-reset-links",
              "email-change-old-links", "mfa-change-sessions"}
CASES = tuple(dict.fromkeys(c for cases in ENTRY_CASES.values() for c in cases))
STATES = ("attempted", "observed", "negative", "blocked", "inconclusive", "n-a")
SOURCES = ("capture", "asset-method", "operator")


def entry_point(path):
    path = path.lower()
    if re.search(r"logout.?all|signout.?all", path):
        return "logout-all"
    if re.search(r"logout|signout", path):
        return "logout"
    if re.search(r"signup|sign.?up|register", path):
        return "signup"
    if re.search(r"forgot|request.?reset", path):
        return "forgot-request"
    if "reset" in path:
        return "password-reset"
    if "invite" in path:
        return "invite"
    if re.search(r"admin.?set", path):
        return "admin-set"
    if re.search(r"oauth|social", path) and "password" in path:
        return "oauth-local"
    if re.search(r"recover|recovery", path):
        return "recovery"
    if re.search(r"mfa|totp|2fa", path) and re.search(r"change|enable|disable", path):
        return "mfa-change"
    if re.search(r"change.?email|email.?change", path):
        return "email-change"
    if re.search(r"change.?password|password.?change", path):
        return "password-change"
    if re.search(r"login|signin|sign.?in", path):
        return "login"
    if "session" in path:
        return "session"
    return "api-direct" if "password" in path else "session"


class AuthPolicyLedger:
    def __init__(self, ctx):
        self.ctx, self.db = ctx, ctx.store.db
        self.journal = ReviewJournal(ctx, "auth-policy")
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.config = validate_auth_policy(ctx.campaign.raw.get("auth_policy", {}))

    def _asset(self, asset_id, url, method):
        if type(asset_id) is not int or asset_id < 1 or method not in HTTP_METHODS:
            raise ValueError("operation needs an endpoint asset and exact HTTP method")
        asset = self.ctx.store.get_asset(asset_id)
        if asset["kind"] != "endpoint" or not asset["in_scope"] or not self.ctx.scope.is_in(url) \
                or endpoint_key(asset["value"]) != endpoint_key(url):
            raise ValueError("operation must match its current in-scope endpoint asset")
        parts = urlsplit(url)
        if parts.query or parts.fragment or parts.username or parts.password:
            raise ValueError("operation URLs cannot include query, credentials or fragment (tokens stay private)")
        return asset

    def declare(self, asset_id, url, method, entry, source_ref, account="unknown",
                role="unknown", tenant="unknown", workflow="unknown",
                representation="unknown", source="operator"):
        self._asset(asset_id, url, method)
        if entry not in ENTRY_CASES or source not in SOURCES:
            raise ValueError("unknown entry point or inventory source")
        for name in (source_ref, account, role, tenant, workflow, representation):
            label(name)
        values = (asset_id, url, method, entry, account, role, tenant, workflow,
                  representation)
        self.db.execute("INSERT OR IGNORE INTO auth_policy_operations"
                        "(asset_id,url,method,entry_point,account,role,tenant,workflow,"
                        "representation,source,source_ref,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (*values, source, source_ref, now()))
        self.db.commit()
        row = self.db.execute("SELECT id FROM auth_policy_operations WHERE "
                              "asset_id=? AND url=? AND method=? AND entry_point=? AND "
                              "account=? AND role=? AND tenant=? AND workflow=? AND representation=?",
                              values).fetchone()
        return {"operation_id": row[0], "cases": self._cases_for(self._operation(row[0])),
                "source": source, "executed": False}

    @staticmethod
    def _cases(entry, method):
        return tuple(c for c in ENTRY_CASES[entry] if method not in ("GET", "HEAD", "OPTIONS")
                     or c not in WRITE_ONLY | {"login-rate-limit", "reset-request-rate-limit"})

    def _cases_for(self, row):
        """One rule-kind/value per password case; no generic observation clears all rules."""
        base = self._cases(row["entry_point"], row["method"])
        if "password-constraint" not in base:
            return base
        from .fields import FieldLedger
        claims = FieldLedger(self.ctx).constraints(row["asset_id"])["claims"]
        rule_keys = sorted({f"password-constraint:{claim['field']}:{claim['kind']}:" +
                            hashlib.sha256(claim["rule_value"].encode()).hexdigest()
                            for claim in claims if claim["method"] == row["method"] and
                            re.search(r"passw(?:or)?d|pwd", claim["field"], re.I)})
        return tuple(c for c in base if c != "password-constraint") + tuple(
            rule_keys or ["password-constraint:undeclared"])

    def sync(self):
        """Import only methods already seen/declared; no guessed POST or URL fetch."""
        assets = [a for a in self.ctx.store.assets("endpoint", in_scope=True)
                  if self.ctx.scope.is_in(a["value"]) and AUTH_PATH.search(urlsplit(a["value"]).path)]
        if len(assets) > 1000:
            raise ValueError("auth inventory exceeds 1000 assets; review a bounded campaign")
        added = 0
        for asset in assets:
            url = asset["value"]
            if urlsplit(url).query or urlsplit(url).fragment:
                continue  # Never retain reset tokens in inventory URLs.
            entry = entry_point(urlsplit(url).path)
            observations = self.ctx.store.observations(asset["id"])
            if len(observations) > 500:
                raise ValueError("auth operation has over 500 observations; review bounded slices")
            seen = set()
            for obs in observations:
                method = (obs.get("method") or "").upper()
                if method not in HTTP_METHODS:
                    continue
                context = obs.get("context") or {}
                meta = context.get("csrf_meta") or {}
                representation = meta.get("content_type") or "unknown"
                if isinstance(representation, str):
                    representation = representation.split(";", 1)[0].strip().lower() or "unknown"
                else:
                    representation = "unknown"
                def safe_claim(value, *, owned=False):
                    if not isinstance(value, str) or not value:
                        return "unknown"
                    try:
                        label(value)
                    except ValueError:
                        return "unknown"
                    if owned and value not in self.config["owned_accounts"]:
                        return "unknown"
                    return value
                fields = (asset["id"], url, method, entry,
                          safe_claim(obs.get("account"), owned=True),
                          safe_claim(context.get("role")), safe_claim(context.get("tenant")),
                          safe_claim(context.get("workflow_state")), safe_claim(representation))
                if fields in seen:
                    continue
                seen.add(fields)
                before = self.db.total_changes
                self.declare(*fields[:4], f"observation:{obs['id']}", *fields[4:], source="capture")
                added += self.db.total_changes - before
            for method in asset["attrs"].get("methods", []):
                method = str(method).upper()
                if method not in HTTP_METHODS or any(v[2] == method for v in seen):
                    continue
                before = self.db.total_changes
                self.declare(asset["id"], url, method, entry, f"asset:{asset['id']}",
                             source="asset-method")
                added += self.db.total_changes - before
        return {"operations_added": added, "total_operations": self.db.execute(
            "SELECT count(*) FROM auth_policy_operations").fetchone()[0],
            "basis": "captured or asset-declared methods only; source labels do not prove an action",
            "executed": False}

    def _operation(self, op_id):
        if type(op_id) is not int or op_id < 1:
            raise ValueError("operation ID must be positive")
        row = self.db.execute("SELECT * FROM auth_policy_operations WHERE id=?", (op_id,)).fetchone()
        if row is None:
            raise ValueError("unknown auth-policy operation")
        self._asset(row["asset_id"], row["url"], row["method"])
        return row

    def _state(self, row, case_id):
        latest = self.db.execute("SELECT review_id FROM auth_policy_case_events "
                                 "WHERE operation_id=? AND case_id=? ORDER BY id DESC LIMIT 1",
                                 (row["id"], case_id)).fetchone()
        if latest is None:
            return "untested"
        try:
            review, data = self.journal.get(latest["review_id"], "case")
            if not isinstance(data, dict) or data.get("operation_id") != row["id"] \
                    or data.get("case_id") != case_id or self._issues(review, data):
                return "stale"
        except (ValueError, KeyError, TypeError, AttributeError):
            return "stale"
        return data["state"]

    def plan(self, operation=None, limit=100, offset=0):
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
            raise ValueError("plan needs limit 1..200 and nonnegative offset")
        if operation is not None:
            self._operation(operation)
        where = "WHERE id=?" if operation is not None else ""
        args = (operation,) if operation is not None else ()
        total = self.db.execute("SELECT count(*) FROM auth_policy_operations " + where,
                                args).fetchone()[0]
        rows = self.db.execute("SELECT * FROM auth_policy_operations " + where +
                               " ORDER BY id LIMIT ? OFFSET ?", (*args, limit, offset)).fetchall()
        operations = []
        for row in rows:
            if not self.ctx.scope.is_in(row["url"]):
                continue
            cases = {c: self._state(row, c) for c in self._cases_for(row)}
            operations.append({"operation_id": row["id"], "asset_id": row["asset_id"],
                               "url": row["url"], "method": row["method"],
                               "entry_point": row["entry_point"], "account": row["account"],
                               "role": row["role"], "tenant": row["tenant"],
                               "workflow": row["workflow"], "representation": row["representation"],
                               "source": row["source"], "source_ref": row["source_ref"],
                               "cases": cases})
        return {"operations": operations, "total": total, "offset": offset,
                "truncated": offset + len(rows) < total, "executed": False,
                "basis": "one operation/context/rule at a time; cases are leads, not findings"}

    def _response(self, request_id, origin):
        if type(request_id) is not int or request_id < 1:
            raise ValueError("evidence refs must be stored response IDs")
        response = self.ctx.store.response(request_id)
        parts = urlsplit(response["url"])
        if not self.ctx.scope.is_in(response["url"]) or f"{parts.scheme}://{parts.netloc}" != origin:
            raise ValueError("evidence response must be scoped to the operation origin")
        return response

    def record(self, operation, case_id, state, refs=None, note="", source="import"):
        row = self._operation(operation)
        if case_id not in self._cases_for(row) or state not in STATES:
            raise ValueError("case is not applicable to this exact operation or state is unknown")
        label(note)
        if source not in ("import", "native", "browser-burp", "owned-lab"):
            raise ValueError("unknown evidence source")
        refs = refs or {}
        if not isinstance(refs, dict) or len(refs) > 8 or any(
                not isinstance(k, str) or not re.fullmatch(r"[a-z][a-z-]{0,40}", k)
                for k in refs):
            raise ValueError("evidence refs need bounded role names")
        observed = state in ("observed", "negative")
        if observed:
            if case_id == "password-constraint:undeclared":
                raise ValueError("observed password rule needs a sourced declared constraint")
            required = ({"baseline", "test", "control", "readback"}
                        if case_id.startswith("password-constraint:") or case_id == "token-derivation" else
                        {"pre-event", "event", "post-event", "invalid-control"}
                        if case_id not in ("login-rate-limit", "reset-request-rate-limit") else
                        {"baseline", "test", "control"})
            if not required <= set(refs) or len(set(refs.values())) != len(refs):
                raise ValueError("observed/negative case needs distinct before, test, control "
                                 "and effect/invalidation responses for its case family")
            if not self.config["policy_reviewed"] or row["account"] not in self.config["owned_accounts"]:
                raise ValueError("observed/negative proof needs a declared owned account and reviewed rules")
            if not self.ctx.policy.allows("active") or row["method"] not in self.ctx.policy.allowed_methods:
                raise ValueError("observed/negative case needs granted method and active campaign")
            if "{" in urlsplit(row["url"]).path:
                raise ValueError("observed/negative case needs a concrete, non-token-bearing operation path")
        snapshots = {}
        for role, request_id in refs.items():
            response = self._response(request_id, f"{urlsplit(row['url']).scheme}://{urlsplit(row['url']).netloc}")
            if observed and (response["error"] or response["status"] is None):
                raise ValueError("proof cannot cite a missing or failed HTTP response")
            if observed and role in ("pre-event", "post-event", "readback") and response["body_complete"] != 1:
                raise ValueError("owned state or session contrast needs a complete captured response")
            if role == ("test" if case_id.startswith("password-constraint:") or case_id in (
                    "token-derivation", "login-rate-limit", "reset-request-rate-limit") else "event") \
                    and ((urlsplit(response["url"]).path != urlsplit(row["url"]).path
                          if observed else endpoint_key(response["url"]) != endpoint_key(row["url"]))
                         or response["method"] != row["method"]):
                raise ValueError("test/event response must be the declared exact operation")
            snapshots[role] = {"request_id": request_id, "sha256": response_hash(response)}
        data = {"operation_id": operation, "operation_sha256": self._operation_hash(row),
                "case_id": case_id, "state": state, "source": source, "note": note,
                "responses": snapshots, "interpretation": "operator-labelled-lead-not-a-finding"}
        review_id = self.journal.append("case", data)
        self.db.execute("INSERT INTO auth_policy_case_events(operation_id,case_id,review_id,created) "
                        "VALUES(?,?,?,?)", (operation, case_id, review_id, now()))
        self.db.commit()
        return {"operation_id": operation, "case": case_id, "state": state,
                "review_id": review_id, "executed": False, "finding_promoted": False}

    @staticmethod
    def _operation_hash(row):
        identity = [row[k] for k in ("asset_id", "url", "method", "entry_point", "account",
                                     "role", "tenant", "workflow", "representation")]
        return hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()

    def _issues(self, review, data):
        issues = self.journal.verify_one(review, data)
        if review["kind"] == "derivation":
            return issues if data.get("conclusion") == "structural-candidate-only; no prediction or token use proved" \
                else issues + ["invalid derivation conclusion"]
        try:
            op = self._operation(data["operation_id"])
            if self._operation_hash(op) != data["operation_sha256"]:
                issues.append("operation changed")
            if data["case_id"] not in self._cases_for(op):
                issues.append("case no longer applies")
            if data["state"] in ("observed", "negative") and (
                    op["account"] not in self.config["owned_accounts"] or
                    op["method"] not in self.ctx.policy.allowed_methods):
                issues.append("account or method grant changed")
            for ref in data["responses"].values():
                origin = f"{urlsplit(op['url']).scheme}://{urlsplit(op['url']).netloc}"
                if response_hash(self._response(ref["request_id"], origin)) != ref["sha256"]:
                    issues.append("response snapshot changed")
        except (KeyError, ValueError, TypeError):
            issues.append("missing operation or response")
        return issues

    def verify(self, limit=100, offset=0):
        rows, page = self.journal.page(limit=limit, offset=offset)
        invalid = []
        for row in rows:
            data = None
            try:
                data = json.loads(row["data"])
                reasons = self._issues(row, data)
            except (ValueError, KeyError, TypeError, AttributeError):
                reasons = ["invalid review snapshot"]
            for reason in reasons:
                invalid.append({"review_id": row["id"], "reason": reason})
            if row["kind"] == "case":
                for event in self.db.execute("SELECT operation_id,case_id FROM auth_policy_case_events "
                                             "WHERE review_id=?", (row["id"],)):
                    if not isinstance(data, dict) or event["operation_id"] != data.get("operation_id") \
                            or event["case_id"] != data.get("case_id"):
                        invalid.append({"review_id": row["id"], "reason": "case event link changed"})
        return {**page, "verified": not invalid and not page["truncated"],
                "invalid": invalid, "executed": False, "finding_promoted": False}

    def status(self, limit=100, offset=0):
        plan = self.plan(limit=limit, offset=offset)
        totals = {}
        for operation in plan["operations"]:
            for state in operation["cases"].values():
                totals[state] = totals.get(state, 0) + 1
        return {**plan, "totals": totals, "basis": "observed = labelled receipt with "
                "responses; not a policy bypass or finding; no live execution"}

    def derive(self, file_name):
        """Transiently inspect owned samples; persist shapes only, never sample values."""
        if not isinstance(file_name, str) or not file_name.startswith(".recon/private/auth-policy/") \
                or ".." in Path(file_name).parts:
            raise ValueError("sample file must be campaign-local .recon/private/auth-policy/")
        path = self.ctx.campaign.root / file_name
        if not path.is_file() or path.is_symlink() or os.stat(path).st_mode & 0o077:
            raise ValueError("sample file must be a regular private file (mode 0600)")
        raw = local(self.ctx.campaign.root, file_name)
        if len(raw) > 20_000:
            raise ValueError("sample file exceeds 20KB")
        doc = json.loads(raw)
        if not isinstance(doc, dict) or set(doc) != {"schema_version", "kind", "samples"} \
                or doc["schema_version"] != 1 or doc["kind"] not in (
                    "reset-token", "otp", "account-id", "session-id", "invite-code", "verify-token"):
            raise ValueError("sample document has invalid schema or kind")
        samples = doc["samples"]
        if not isinstance(samples, list) or not 2 <= len(samples) <= 10:
            raise ValueError("derivation needs 2..10 owned samples")
        clean = []
        for sample in samples:
            if not isinstance(sample, dict) or set(sample) != {"account", "value"} \
                    or sample["account"] not in self.config["owned_accounts"] \
                    or not isinstance(sample["value"], str) \
                    or not 1 <= len(sample["value"]) <= 512:
                raise ValueError("every sample needs an owned account and bounded value")
            clean.append(sample)
        if len({s["account"] for s in clean}) < 2:
            raise ValueError("derivation candidates need two distinct owned accounts")
        values = [s["value"] for s in clean]
        numeric = all(v.isascii() and v.isdecimal() for v in values)
        uuids = []
        for v in values:
            try:
                uuids.append(uuid.UUID(v).version)
            except ValueError:
                uuids.append(None)
        # Base64-decoded account labels are only structural clues, not a token prediction.
        def contains_owned_label(value, account):
            try:
                decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
            except (ValueError, base64.binascii.Error):
                return False
            return account.encode() in decoded
        data = {"kind": doc["kind"], "sample_count": len(clean),
                "owned_account_count": len({s["account"] for s in clean}),
                "source_file_sha256": hashlib.sha256(raw).hexdigest(),
                "uniform_length": len({len(v) for v in values}) == 1,
                "numeric_monotonic": numeric and all(int(a) < int(b)
                                                    for a, b in zip(values, values[1:])),
                "time_uuid_format": all(v in (1, 6) for v in uuids),
                "base64_contains_owned_label": any(contains_owned_label(v, s["account"])
                                                   for v, s in zip(values, clean)),
                "conclusion": "structural-candidate-only; no prediction or token use proved",
                "source_retained": False}
        review_id = self.journal.append("derivation", data)
        return {"review_id": review_id, **data, "executed": False,
                "finding_promoted": False}
