"""Private, bounded journals for offline reviews. No network or job scheduling."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from .callbacks import local_bytes
from .extract import SECRET_PATTERNS
from .store import now

MAX_BYTES = 5_000_000
MAX_ITEMS = 500


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def local(root, name):
    if not isinstance(name, str) or not name or Path(name).is_absolute():
        raise ValueError("review files must be campaign-relative")
    base = Path(root).resolve()
    target = base / name
    if ".." in Path(name).parts:
        raise ValueError("review file escapes campaign")
    for part in (target, *target.parents):
        if part == base:
            break
        if part.is_symlink():
            raise ValueError("review evidence symlinks are refused")
    return local_bytes(base, name)


def document(root, name):
    value = json.loads(local(root, name))
    if not isinstance(value, dict):
        raise ValueError("review document must be an object")
    return value


def fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or (
            set(value) - set(required) - set(optional)):
        raise ValueError("review document has missing or unknown fields")


def label(value):
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:/@+-]{1,160}", value)
            or any(p.search(value) for p in SECRET_PATTERNS.values())):
        raise ValueError("review labels must be bounded and value-free")
    return value


def policy(ctx):
    # Keep only a hash, never export campaign rules or credentials.
    return digest(canonical(ctx.campaign.raw).encode())


class ReviewJournal:
    def __init__(self, ctx, domain):
        if domain not in ("cache", "http-framing", "rce", "auth-policy"):
            raise ValueError("unknown review journal")
        self.ctx, self.db, self.domain = ctx, ctx.store.db, domain
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS offline_reviews(
          id INTEGER PRIMARY KEY, domain TEXT NOT NULL, kind TEXT NOT NULL,
          data TEXT NOT NULL, sha256 TEXT NOT NULL, policy_hash TEXT NOT NULL,
          created TEXT NOT NULL, UNIQUE(domain,kind,sha256));
        """)
        self.db.commit()

    def retain(self, raw, source=None):
        if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
            raise ValueError("review evidence exceeds five megabytes")
        sha = digest(raw)
        folder = self.ctx.campaign.root / ".recon" / "offline-review" / self.domain
        for part in (folder, *folder.parents):
            if part == self.ctx.campaign.root:
                break
            if part.is_symlink():
                raise ValueError("review evidence directory is a symlink")
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = folder / sha
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if path.is_symlink() or digest(local(self.ctx.campaign.root,
                    path.relative_to(self.ctx.campaign.root).as_posix())) != sha:
                raise ValueError("retained review evidence was changed")
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
        receipt = {"path": path.relative_to(self.ctx.campaign.root).as_posix(),
                   "sha256": sha, "bytes": len(raw)}
        if source is not None:
            if digest(local(self.ctx.campaign.root, source)) != sha:
                raise ValueError("review source changed during retention")
            receipt["source"] = source
        return receipt

    def artifact(self, name):
        return self.retain(local(self.ctx.campaign.root, name), source=name)

    def append(self, kind, data, commit=True):
        data = {**data, "policy_hash": policy(self.ctx), "domain": self.domain, "kind": kind}
        encoded = canonical(data)
        sha = digest(encoded.encode())
        self.db.execute("INSERT OR IGNORE INTO offline_reviews"
                        "(domain,kind,data,sha256,policy_hash,created) VALUES(?,?,?,?,?,?)",
                        (self.domain, kind, encoded, sha, data["policy_hash"], now()))
        if commit:
            self.db.commit()
        row = self.db.execute("SELECT id FROM offline_reviews WHERE domain=? AND kind=? "
                              "AND sha256=?", (self.domain, kind, sha)).fetchone()
        return row[0]

    def get(self, record_id, kind=None):
        if type(record_id) is not int or record_id < 1:
            raise ValueError("review reference must be a positive integer")
        row = self.db.execute("SELECT * FROM offline_reviews WHERE id=? AND domain=?",
                              (record_id, self.domain)).fetchone()
        if row is None or (kind is not None and row["kind"] != kind):
            raise ValueError("no matching campaign-local review reference")
        return row, json.loads(row["data"])

    def verify_one(self, row, data):
        issues = []
        if digest(canonical(data).encode()) != row["sha256"]:
            issues.append("review snapshot changed")
        if data.get("domain") != row["domain"] or data.get("kind") != row["kind"]:
            issues.append("review identity differs from snapshot")
        if data.get("policy_hash") != row["policy_hash"]:
            issues.append("policy column differs from snapshot")
        if row["policy_hash"] != policy(self.ctx):
            issues.append("policy changed; stale")
        for role, receipt in data.get("artifacts", {}).items():
            try:
                raw = local(self.ctx.campaign.root, receipt["path"])
                if digest(raw) != receipt["sha256"] or len(raw) != receipt["bytes"]:
                    raise ValueError("retained artifact changed")
                if "source" in receipt and digest(local(
                        self.ctx.campaign.root, receipt["source"])) != receipt["sha256"]:
                    raise ValueError("original source changed")
            except (ValueError, OSError, KeyError, TypeError):
                issues.append("artifact invalid: " + role)
        return issues

    def page(self, kind=None, limit=100, offset=0):
        if type(limit) is not int or not 1 <= limit <= MAX_ITEMS or (
                type(offset) is not int or offset < 0):
            raise ValueError("review page needs limit 1..500 and nonnegative offset")
        where, args = "domain=?", [self.domain]
        if kind:
            where += " AND kind=?"
            args.append(kind)
        total = self.db.execute("SELECT count(*) FROM offline_reviews WHERE " + where,
                                args).fetchone()[0]
        rows = self.db.execute("SELECT * FROM offline_reviews WHERE " + where +
                               " ORDER BY id LIMIT ? OFFSET ?", (*args, limit, offset)).fetchall()
        return rows, {"total": total, "visible": len(rows), "offset": offset,
                      "truncated": offset + len(rows) < total,
                      "next_offset": offset + len(rows) if offset + len(rows) < total else None}

    def verify(self, limit=100, offset=0):
        rows, page = self.page(limit=limit, offset=offset)
        issues = []
        for row in rows:
            try:
                data = json.loads(row["data"])
                reasons = self.verify_one(row, data)
            except (ValueError, TypeError, AttributeError):
                reasons = ["invalid review snapshot"]
            issues.extend({"id": row["id"], "reason": reason} for reason in reasons)
        return {**page, "ok": not issues, "issues": issues,
                "complete": offset == 0 and not page["truncated"], "executed": False,
                "finding_promoted": False}
