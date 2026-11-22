"""Conservative HTTP/1 capture lint, not a desync detector or network transport.

All messages are read from local files. Rejection is a framing-policy observation,
not evidence that two real parsers disagree. No payload generation or forwarding.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .offline_review import ReviewJournal, canonical, digest, document, local

TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
MAX_HEADER = 65_536
MAX_MESSAGE = 2_000_000


def split_message(raw):
    """Internal raw view. Callers must never print header values or start lines."""
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE:
        raise ValueError("HTTP review accepts at most two megabytes")
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep or len(head) > MAX_HEADER:
        return None
    lines = head.split(b"\r\n")
    if len(lines) > 201:
        return None
    headers = []
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not TOKEN.fullmatch(name) or line.startswith((b" ", b"\t")):
            return None
        if any(c < 32 and c != 9 or c == 127 for c in value):
            return None
        headers.append((name.decode("ascii").lower(), value.strip(b" \t")))
    return lines[0], headers, body


def _chunked_length(body):
    """Validate one bounded chunked message; reject suffixes and trailer fields."""
    offset, total = 0, 0
    for _ in range(4096):
        end = body.find(b"\r\n", offset)
        if end < 0 or end - offset > 128:
            return None
        size = body[offset:end]
        # Extensions and trailers are intentionally outside this small validator.
        if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size):
            return None
        count = int(size, 16)
        offset = end + 2
        if count == 0:
            return total if body[offset:] == b"\r\n" else None
        if count > MAX_MESSAGE or body[offset + count:offset + count + 2] != b"\r\n":
            return None
        offset += count + 2
        total += count
    return None


def inspect_http1(raw, kind="request"):
    if kind not in ("request", "response"):
        raise ValueError("HTTP review kind must be request or response")
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE:
        raise ValueError("HTTP review accepts at most two megabytes")
    issues, notes = [], []
    parsed = split_message(raw)
    if parsed is None:
        issues.append("invalid-or-incomplete-header-block")
        return {"verdict": "reject", "issues": issues, "notes": [], "body_complete": False,
                "message_sha256": digest(raw), "bytes": len(raw), "kind": kind,
                "smuggling_confirmed": False}
    start, headers, body = parsed
    if kind == "request":
        match = re.fullmatch(rb"([A-Z]+) ([^\x00-\x20\x7f]+) HTTP/1\.([01])", start)
    else:
        match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9][0-9])(?: [\x20-\x7e]*)?", start)
    if not match:
        issues.append("unsupported-or-invalid-start-line")
    names = [name for name, _ in headers]
    values = lambda name: [value for field, value in headers if field == name]
    lengths, transfers = values("content-length"), values("transfer-encoding")
    if len(lengths) > 1:
        issues.append("duplicate-content-length")
    if len(transfers) > 1:
        issues.append("duplicate-transfer-encoding")
    if lengths and transfers:
        issues.append("content-length-with-transfer-encoding")
    if kind == "request" and start.endswith(b"HTTP/1.1"):
        if len(values("host")) != 1 or not values("host")[0]:
            issues.append("missing-or-duplicate-host")
    complete = True
    if lengths:
        if len(lengths[0]) > 12 or not re.fullmatch(rb"[0-9]+", lengths[0]):
            issues.append("invalid-content-length")
        elif int(lengths[0]) != len(body):
            issues.append("content-length-body-mismatch")
            complete = False
    elif transfers:
        if transfers != [b"chunked"]:
            notes.append("unsupported-transfer-coding")
            complete = False
        elif _chunked_length(body) is None:
            issues.append("invalid-or-unsupported-chunked-body")
            complete = False
    elif kind == "request" and body:
        issues.append("unframed-request-body-or-following-message")
        complete = False
    elif kind == "response":
        notes.append("close-delimited-or-request-dependent-body")
        complete = False
    if any(name in names for name in ("connection", "upgrade")):
        notes.append("connection-lifecycle-not-established")
    return {"verdict": "reject" if issues else ("inconclusive" if notes else "well-formed-observation"),
            "issues": issues, "notes": notes, "body_complete": complete and not issues,
            "message_sha256": digest(raw), "bytes": len(raw), "kind": kind,
            "header_occurrences": len(headers), "duplicate_header_count": len(names) - len(set(names)),
            "smuggling_confirmed": False}


def _attributed(raw, url, kind):
    result = inspect_http1(raw, kind)
    parsed = split_message(raw)
    parts = urlsplit(url)
    if kind == "request" and parsed:
        target = parsed[0].split(b" ")
        if len(target) == 3:
            wire_target = target[1].decode("ascii", "replace")
            expected = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
            hosts = [v.decode("ascii", "replace") for k, v in parsed[1] if k == "host"]
            if wire_target != expected or hosts != [parts.netloc]:
                result["issues"].append("capture-url-authority-or-target-mismatch")
                result["verdict"] = "reject"
    return result


class HttpReview:
    def __init__(self, ctx):
        self.ctx, self.journal = ctx, ReviewJournal(ctx, "http-framing")

    def inspect(self, filename, url, kind="request"):
        if not isinstance(url, str) or len(url) > 16_384 or not self.ctx.scope.is_in(url):
            raise ValueError("HTTP review needs an in-scope capture URL; nothing is requested")
        parts = urlsplit(url)
        if parts.fragment:
            raise ValueError("capture attribution URL cannot contain a fragment")
        raw = local(self.ctx.campaign.root, filename)
        result = _attributed(raw, url, kind)
        artifact = self.journal.artifact(filename)
        data = {"origin": f"{parts.scheme}://{parts.netloc}",
                "url_sha256": digest(url.encode()), "analysis": result,
                "artifacts": {"capture": artifact, "attribution": self.journal.retain(
                    canonical({"url": url}).encode())}}
        record_id = self.journal.append("inspection", data)
        return {"id": record_id, **result, "executed": False, "finding_promoted": False}

    def show(self, record_id):
        row, data = self.journal.get(record_id, "inspection")
        return {"id": record_id, "origin": data["origin"], **data["analysis"],
                "integrity_issues": self.journal.verify_one(row, data), "executed": False,
                "finding_promoted": False}

    def status(self, limit=100, offset=0):
        rows, page = self.journal.page("inspection", limit, offset)
        return {**page, "rows": [self.show(row["id"]) for row in rows], "executed": False,
                "smuggling_confirmed": False, "finding_promoted": False}

    def verify(self, limit=100, offset=0):
        result = self.journal.verify(limit, offset)
        # Recompute the deterministic lint in addition to checking file hashes.
        rows, _ = self.journal.page(limit=limit, offset=offset)
        for row in rows:
            try:
                _, data = self.journal.get(row["id"], "inspection")
                raw = local(self.ctx.campaign.root, data["artifacts"]["capture"]["path"])
                url = document(self.ctx.campaign.root, data["artifacts"]["attribution"]["path"])["url"]
                analysis = _attributed(raw, url, data["analysis"]["kind"])
                if analysis != data["analysis"] or digest(url.encode()) != data["url_sha256"]:
                    raise ValueError("framing analysis changed")
            except (ValueError, OSError, KeyError, TypeError):
                result["issues"].append({"id": row["id"], "reason": "framing recheck failed"})
        result["ok"] = not result["issues"]
        result["smuggling_confirmed"] = False
        return result
