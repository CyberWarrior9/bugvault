"""Offline file-upload lifecycle ledger: sink inventory, case readiness and evidence facts.

No HTTP client, upload executor, payload generator, scanner or callback listener.
Intake, storage, processing, publication, retrieval and deletion are separate,
artifact-backed facts: a 201, a stored marker, a thumbnail or a callback each
establishes only its own stage. Execution needs an attributable consumer log, a
demonstrated effect, a replay and a distinct control. Nothing here promotes a
finding. Fixtures are tiny inert marker files for owned labs and baselines.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import secrets
import struct
import zipfile
import zlib
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .authz import SECRET_RE, digest
from .callbacks import (approved_callback_host, local_bytes, require_callback_url, timestamp,
                        valid_marker, validate_callback_hosts)
from .campaign import OutOfScope, norm_host, validate_upload
from .extract import endpoint_key, origin_of
from .score import applicable_classes, is_inferred_only, ssrf_parameters
from .store import now

SCHEMA = """
CREATE TABLE IF NOT EXISTS upload_sinks(
 id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
 url TEXT NOT NULL, method TEXT NOT NULL, field TEXT NOT NULL, transport TEXT NOT NULL,
 surface TEXT NOT NULL, basis TEXT NOT NULL, sources TEXT NOT NULL,
 note TEXT NOT NULL DEFAULT '', created TEXT NOT NULL,
 UNIQUE(asset_id, method, url, field, transport));
CREATE TABLE IF NOT EXISTS upload_contexts(
 id INTEGER PRIMARY KEY, sink_id INTEGER NOT NULL REFERENCES upload_sinks(id),
 account TEXT NOT NULL, role TEXT NOT NULL, tenant TEXT NOT NULL, workflow TEXT NOT NULL,
 capture_key TEXT NOT NULL, basis TEXT NOT NULL, observation_ids TEXT NOT NULL,
 facets TEXT NOT NULL, updated TEXT NOT NULL,
 UNIQUE(sink_id, account, role, tenant, workflow, capture_key));
CREATE TABLE IF NOT EXISTS upload_events(
 id INTEGER PRIMARY KEY, context_id INTEGER NOT NULL REFERENCES upload_contexts(id),
 case_id TEXT NOT NULL, state TEXT NOT NULL, channel TEXT NOT NULL, grant TEXT NOT NULL,
 marker TEXT NOT NULL, control_marker TEXT NOT NULL, facts TEXT NOT NULL,
 layer TEXT NOT NULL, request_ref TEXT NOT NULL, response_status INTEGER,
 route TEXT NOT NULL, stop_trigger TEXT NOT NULL, served_headers TEXT NOT NULL,
 requests INTEGER NOT NULL, bytes INTEGER NOT NULL, objects INTEGER NOT NULL,
 object_ref TEXT NOT NULL, tool_refs TEXT NOT NULL, root_key TEXT NOT NULL,
 retention_deadline TEXT NOT NULL, policy_hash TEXT NOT NULL, facet_hash TEXT NOT NULL,
 note TEXT NOT NULL, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS upload_events_context ON upload_events(context_id, case_id, id);
CREATE TABLE IF NOT EXISTS upload_artifacts(
 event_id INTEGER NOT NULL REFERENCES upload_events(id), role TEXT NOT NULL,
 path TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, source_path TEXT NOT NULL,
 PRIMARY KEY(event_id, role));
CREATE TABLE IF NOT EXISTS upload_callbacks(
 id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES upload_events(id),
 kind TEXT NOT NULL, host TEXT NOT NULL, classification TEXT NOT NULL,
 sent_at TEXT NOT NULL, observed_at TEXT NOT NULL, deadline TEXT NOT NULL,
 control_marker TEXT NOT NULL, job_id TEXT NOT NULL, artifacts TEXT NOT NULL,
 note TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS upload_cleanup(
 id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES upload_events(id),
 outcome TEXT NOT NULL, artifacts TEXT NOT NULL, note TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS upload_stops(
 id INTEGER PRIMARY KEY, host TEXT NOT NULL, stop_kind TEXT NOT NULL,
 event_id INTEGER REFERENCES upload_events(id), created TEXT NOT NULL,
 cleared TEXT NOT NULL DEFAULT '', clear_note TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS upload_fixtures(
 marker TEXT PRIMARY KEY, control_marker TEXT NOT NULL, kind TEXT NOT NULL,
 path TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL,
 control_path TEXT NOT NULL, control_sha256 TEXT NOT NULL, created TEXT NOT NULL);
"""

MAX_SINKS = 2000
MAX_CONTEXTS = 50
MAX_FIXTURE = 4096
TINY_LIVE_BYTES = 4096
WRITE_METHODS = ("POST", "PUT", "PATCH")
TRANSPORTS = ("multipart", "batch", "raw-body", "signed-storage", "resumable", "url-import", "unknown")
FILE_TRANSPORTS = ("batch", "multipart", "raw-body", "resumable", "signed-storage", "unknown")
SURFACE_RULES = (
    ("avatar", re.compile(r"avatar|profile[-_]?(?:photo|image|picture)|logo", re.I)),
    ("attachment", re.compile(r"attach", re.I)),
    ("import", re.compile(r"import|csv|xlsx|bulk", re.I)),
    ("archive", re.compile(r"archive|zip|backup|restore", re.I)),
    ("template", re.compile(r"template|theme", re.I)),
    ("preview", re.compile(r"preview|thumbnail|render|convert", re.I)),
    ("document", re.compile(r"document|docs?(?:/|$)|pdf|report", re.I)),
    ("media", re.compile(r"media|video|audio|image|photo|picture", re.I)),
)
SURFACES = tuple(name for name, _ in SURFACE_RULES) + ("other",)
SIGNED_RE = re.compile(r"presign|pre-sign|signed[-_]?url|upload[-_]?url|sign[-_]?upload|"
                       r"direct[-_]?upload|sas[-_]?token", re.I)
RESUMABLE_RE = re.compile(r"resumable|(?:^|/)tus(?:/|$)|chunk|upload[-_]?session|"
                          r"multipart/(?:init|start|complete|part)", re.I)
FILE_FIELDS = {"file", "files", "upload", "uploads", "upfile", "avatar", "image", "images",
               "photo", "picture", "attachment", "attachments", "document", "doc", "media",
               "logo", "csv", "archive", "import", "blob", "asset", "thumbnail", "video",
               "audio", "pdf", "spreadsheet"}
STORAGE_HOST_RE = re.compile(r"(?:^|[.-])(?:s3|storage|blob|buckets?|cdn|r2|spaces|cloudfront|"
                             r"gcs|files?|uploads?|media|assets?)(?:[.-]|$)", re.I)

CHANNELS = ("browser", "burp", "native", "scanner", "lab", "review")
LIVE_CHANNELS = ("browser", "burp", "native", "scanner")
STATES = ("attempted", "accepted-inert", "rejected", "pending", "blocked", "inconclusive",
          "impact-demonstrated", "review-candidate", "review-clear", "n-a")
TRAFFIC_STATES = ("attempted", "accepted-inert", "rejected", "pending", "impact-demonstrated")
REVIEW_STATES = ("review-candidate", "review-clear", "blocked", "inconclusive", "n-a")
NOTE_STATES = ("rejected", "blocked", "inconclusive", "n-a", "review-candidate", "review-clear")
CLOSED_STATES = ("accepted-inert", "rejected", "review-clear", "n-a", "impact-demonstrated",
                 "not-applicable")
FACTS = ("accepted", "stored", "reachable", "processed", "served", "executed", "effect")
ROLES = ("original", "control", "request", "response", "retrieval", "derivative", "worker-log",
         "edge-log", "origin-log", "storage-log", "consumer-log", "effect", "replay", "review",
         "receipt")
CALLBACK_ROLES = ("receiver-health", "receiver-log", "worker-log")
CALLBACK_KINDS = ("dns", "http", "worker-trace")
LAYERS = ("unconfirmed", "edge", "origin", "worker", "storage")
ROUTES = ("file-upload", "xss", "ssrf", "xxe", "file-read", "ssti", "idor-bola",
          "access-control", "execution")
STOP_KINDS = ("challenge", "captcha", "rate-limit", "server-error", "degradation", "incident",
              "real-user-data", "unapproved-host", "budget", "receiver-lost", "cleanup-unresolved")
CLEANUP_OUTCOMES = ("deleted", "aborted", "expired", "retained-by-owner", "failed", "unverified")
CLEANUP_DONE = ("deleted", "aborted", "expired", "retained-by-owner")
SERVED_HEADERS = ("content-type", "content-disposition", "x-content-type-options",
                  "content-security-policy", "cache-control", "cross-origin-resource-policy")
FIXTURE_KINDS = ("text", "png", "zip")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# Fixture lint only: tiny inert fixtures must not carry server- or browser-interpretable markup.
ACTIVE_MARKERS = (b"<?", b"<%", b"<script", b"javascript:", b"<!entity", b"<!--#")

_FILE = FILE_TRANSPORTS
_CASE_ROWS = (
    ("intake-normal", None, "live", None, 9,
     "One allowed small owned marker file through the intended feature; observe the request, "
     "returned ID, status, owned retrieval and delete action.",
     "Ordinary lifecycle baseline; a 201/200 alone is not a defect."),
    ("intake-role", "cross-account", "live", None, 6,
     "Documented permission for the uploader role versus a second owned test role on the same "
     "operation; never another user's object.",
     "Attribute acceptance or denial to the role and exact operation, not merely the host."),
    ("contrast-extension", "contrast", "live", _FILE, 7,
     "Inert unneeded extension versus an allowed same-size control; no executable suffix.",
     "Records the validation outcome and generated name; acceptance is not code execution."),
    ("contrast-media-type", "contrast", "live", _FILE, 6,
     "The same valid benign bytes declared with two ordinary media types the policy permits.",
     "A client-declared type is not a content check; record the server verdict only."),
    ("contrast-format", "contrast", "live", _FILE, 7,
     "Small benign wrong-format bytes under a nominally accepted extension versus a valid control.",
     "Separates signature/format checks from declared-type checks; no active or polyglot content."),
    ("contrast-filename", "contrast", "live", _FILE, 5,
     "Benign case, spacing, Unicode or length variant of an ordinary name versus a simple name.",
     "Compare displayed name, stored key and download header; no traversal, overwrite or "
     "metacharacter names on a live target."),
    ("batch-items", "contrast", "live", ("batch", "multipart"), 4,
     "Two tiny permitted files with different markers; compare per-item and whole-batch verdicts.",
     "An accepted batch must not mask an unvalidated item; no exhaustion."),
    ("size-boundary", "contrast", "tiny", _FILE, 4,
     "Tiny boundary around a documented tiny or lab cap; count multipart envelope bytes separately.",
     "Never cross a large live threshold; use configuration review or an owned lab."),
    ("quota-count", None, "review", None, 2,
     "Compare the declared quota with a one-at-a-time owned-object count; read configuration "
     "for larger bounds.",
     "No storage-filling test; stop before any quota or cost impact."),
    ("signed-storage", "transport", "live", ("signed-storage",), 6,
     "Review signing policy, object key, finalization and publish checks; write only to an "
     "explicitly in-scope owned bucket.",
     "An accepted storage PUT is not application approval or publication; the storage host "
     "needs its own scope."),
    ("resumable-assembly", "transport", "live", ("resumable",), 5,
     "Two tiny owned parts below the cap; compare final length, declared total and finalization.",
     "Whole-object limits must hold, not only per-part limits."),
    ("resumable-abort", "transport", "live", ("resumable",), 4,
     "Compare owned session and partial visibility, abort, expiry and cleanup.",
     "No cross-owner session IDs on real users; account for residual parts and cost."),
    ("url-import", "transport", "review-unless-callback", ("url-import",), 6,
     "Confirm a documented import-from-URL feature; fetch only from an approved owned receiver.",
     "Fetched bytes, import job and publication are separate facts; no internal address or "
     "redirect probing."),
    ("derivative-metadata", "derivative", "live", _FILE, 6,
     "One valid tiny image with a harmless unique metadata marker; compare the original with "
     "the thumbnail or metadata display.",
     "A derivative or job record proves processing only, not an unsafe parser or command execution."),
    ("worker-observation", "derivative", "live", None, 5,
     "Observe ordinary preview/transcode status and owner-supplied worker logs.",
     "Associate processing with a job ID and version; no crafted converter directives."),
    ("xml-document", None, "review", None, 5,
     "Review parser configuration and external-resource policy; an ordinary valid document in a lab.",
     "XML inside a format is a candidate only; entity resolution needs actual external evidence."),
    ("quarantine-scan", "derivative", "live", None, 5,
     "Observe pending, accepted/rejected and published transitions under normal polling.",
     "No visibility before approval; a scanner alert is not proof of malware execution."),
    ("archive-extraction", "derivative", "live", _FILE, 4,
     "Tiny flat archive of owned benign files; inspect the extraction destination and entries.",
     "Normal extraction is not path escape; review symlink, canonical-path and expanded-size "
     "controls in configuration or an owned lab."),
    ("process-arguments", None, "review", None, 5,
     "Review the worker invocation; a local stub records inert argument boundaries without "
     "running a utility.",
     "A process name or argument sink is a candidate only."),
    ("inclusion-path", None, "review", None, 5,
     "Review preview/include/path mapping with a lab-only owned file reference.",
     "Needs a separately influenced path and real read semantics before any file-read "
     "hypothesis; no system-file access."),
    ("retrieval-policy", None, "live", None, 8,
     "Fetch only your own object; record origin, Content-Type, Content-Disposition, "
     "X-Content-Type-Options and embedding context.",
     "Static bytes or an attachment do not show execution; browser rendering is separate from "
     "server handling."),
    ("published-authz", "cross-account", "live", None, 8,
     "A second authorized test account requests the first account's test-owned object, if "
     "the policy allows the attempt.",
     "A cross-account consequence needs replay and a distinct control; never guess strangers' IDs."),
    ("edge-callback", None, "live", None, 4,
     "Correlate one inert request with owner edge/origin/worker logs; with an approved receiver, "
     "record health, a unique token and a control.",
     "An edge block stays layer-unconfirmed without correlation; DNS/HTTP contact is not code "
     "execution or an internal read."),
    ("cleanup", None, "live", None, 10,
     "Delete or abort your own original, derivatives and partial parts; record receipts and "
     "retention gaps.",
     "Unverified cleanup is a stop and escalation, not permission to leave artifacts."),
)
CASES: Dict[str, Dict[str, Any]] = {
    row[0]: {"n": index + 1, "grant": row[1], "mode": row[2], "transports": row[3],
             "priority": row[4], "compare": row[5], "limit": row[6]}
    for index, row in enumerate(_CASE_ROWS)}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _host(url: str) -> str:
    return norm_host(urlsplit(url).hostname or "")


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _lab_host(host: str) -> bool:
    """Owned-lab evidence may only describe loopback or reserved test names."""
    try:
        return ip_address(host).is_loopback
    except ValueError:
        pass
    return host == "localhost" or host.endswith((".localhost", ".test", ".invalid", ".example"))


def _safe_text(value: Any, what: str, limit: int = 2000) -> None:
    if not isinstance(value, str) or len(value) > limit or any(
            ord(c) < 32 and c not in "\n\t" for c in value):
        raise ValueError(f"{what} must be bounded single-purpose text")
    if SECRET_RE.search(value.encode()):
        raise ValueError(f"{what} appears to contain a raw secret; redact it")


def _leaf(name: str) -> str:
    words = re.findall(r"[a-z][a-z0-9_-]*", name.lower())
    return re.sub(r"[^a-z0-9]", "", words[-1]) if words else ""


def _file_field(name: Any) -> bool:
    return isinstance(name, str) and 0 < len(name) <= 200 and _leaf(name) in FILE_FIELDS


def _transport(url: str, method: str, types, fields: List[str], names: List[str]) -> str:
    path = urlsplit(url).path
    if SIGNED_RE.search(path):
        return "signed-storage"
    if RESUMABLE_RE.search(path):
        return "resumable"
    if not fields and ssrf_parameters(names):
        return "url-import"
    if fields or any(t.startswith("multipart/") for t in types):
        return "batch" if len(fields) > 1 or any(f.endswith("[]") for f in fields) else "multipart"
    if method == "PUT" or any(t == "application/octet-stream" or
                              t.startswith(("image/", "video/", "audio/")) for t in types):
        return "raw-body"
    return "unknown"


def _sink_fields(transport: str, fields: List[str], names: List[str]) -> List[str]:
    if transport == "batch":
        return ["+".join(fields)[:300] or "(batch)"]
    if fields:
        return fields
    if transport == "url-import":
        return ssrf_parameters(names)[:5] or ["(url)"]
    return [{"raw-body": "(body)", "signed-storage": "(signed-request)",
             "resumable": "(chunk)"}.get(transport, "(field-unknown)")]


def _surface(url: str) -> str:
    path = urlsplit(url).path
    return next((name for name, pattern in SURFACE_RULES if pattern.search(path)), "other")


def _candidate(asset: Dict[str, Any], ops: List[Dict[str, Any]]) -> bool:
    attrs = asset.get("attrs") or {}
    if "upload-declared" in (attrs.get("sources") or []) or "file-upload" in applicable_classes(asset):
        return True
    types = list(attrs.get("content_types") or [])
    for op in ops:
        types += list(op["attrs"].get("content_types") or []) + list(op["attrs"].get("spec_content_types") or [])
    return any(isinstance(t, str) and t.lower().startswith("multipart/") for t in types)


def _parse_facts(items: Any) -> Dict[str, str]:
    if items is None:
        return {}
    if isinstance(items, dict):
        pairs = list(items.items())
    elif isinstance(items, list):
        pairs = []
        for item in items:
            if not isinstance(item, str) or "=" not in item:
                raise ValueError("facts are STAGE=yes|no strings")
            key, _, value = item.partition("=")
            pairs.append((key.strip(), value.strip()))
    else:
        raise ValueError("facts must be a list of STAGE=yes|no strings")
    out: Dict[str, str] = {}
    for key, value in pairs:
        if key not in FACTS or value not in ("yes", "no") or key in out:
            raise ValueError(f"facts are unique STAGE=yes|no pairs with stage in {list(FACTS)}")
        out[key] = value
    return out


def _served(headers: Any) -> Dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, dict) or len(headers) > len(SERVED_HEADERS):
        raise ValueError("served headers must be a small JSON object")
    out = {}
    for name, value in headers.items():
        key = str(name).lower()
        if key not in SERVED_HEADERS or not isinstance(value, str) or len(value) > 300 or \
                any(ord(c) < 32 for c in value):
            raise ValueError(f"served headers are limited to {list(SERVED_HEADERS)} with short values")
        out[key] = value
    return out


def mint_marker(prefix: str = "bvup") -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + kind + data +
            struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))


def fixture_bytes(kind: str, marker: str, size: Optional[int] = None) -> Tuple[bytes, str]:
    """Tiny inert marker files: plain text, a 1x1 PNG with a text chunk, a flat stored archive."""
    if not valid_marker(marker):
        raise ValueError("fixture marker must be a valid owned marker")
    if kind == "text":
        base = f"bugvault inert upload fixture\nmarker={marker}\n".encode()
        if size is None:
            return base, "txt"
        if type(size) is not int or not len(base) <= size <= MAX_FIXTURE:
            raise ValueError(f"text fixture size must be {len(base)}..{MAX_FIXTURE} bytes")
        return base + b"." * (size - len(base)), "txt"
    if size is not None:
        raise ValueError("--size applies to text fixtures only")
    if kind == "png":
        header = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
        return (PNG_SIGNATURE + _chunk(b"IHDR", header) +
                _chunk(b"tEXt", b"Comment\x00" + marker.encode()) +
                _chunk(b"IDAT", zlib.compress(b"\x00\x80")) + _chunk(b"IEND", b"")), "png"
    if kind == "zip":
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            for label in ("a", "b"):
                info = zipfile.ZipInfo(f"{label}-{marker}.txt", date_time=(1980, 1, 1, 0, 0, 0))
                info.external_attr = 0o100644 << 16
                archive.writestr(info, f"bugvault inert archive entry {label}\nmarker={marker}\n")
        return buffer.getvalue(), "zip"
    raise ValueError(f"fixture kind must be one of {list(FIXTURE_KINDS)}")


def control_bytes(control_marker: str) -> bytes:
    return f"bugvault inert upload control\ncontrol={control_marker}\n".encode()


def _text_issues(blob: bytes, label: str, allow_nul: bool = False) -> List[str]:
    low = blob.lower()
    issues = [f"{label} contains active markup {token.decode()!r}"
              for token in ACTIVE_MARKERS if token in low]
    if not allow_nul and b"\x00" in blob:
        issues.append(f"{label} contains NUL bytes")
    return issues


def _png_issues(data: bytes) -> List[str]:
    if not data.startswith(PNG_SIGNATURE):
        return ["missing PNG signature"]
    issues, kinds, pos = [], [], len(PNG_SIGNATURE)
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        kind, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]
        crc = data[pos + 8 + length:pos + 12 + length]
        if len(body) != length or len(crc) != 4 or \
                struct.unpack(">I", crc)[0] != zlib.crc32(kind + body) & 0xFFFFFFFF:
            return issues + ["corrupt PNG chunk"]
        kinds.append(kind)
        if kind == b"tEXt":
            issues += _text_issues(body, "PNG text chunk", allow_nul=True)
        pos += 12 + length
    if pos != len(data) or not kinds or kinds[0] != b"IHDR" or kinds[-1] != b"IEND" or \
            set(kinds) - {b"IHDR", b"tEXt", b"IDAT", b"IEND"}:
        issues.append("PNG uses unexpected or misordered chunks")
    return issues


def _zip_issues(data: bytes) -> List[str]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return ["not a readable archive"]
    issues, total = [], 0
    with archive:
        entries = archive.infolist()
        if not 1 <= len(entries) <= 8:
            issues.append("archive must hold 1..8 entries")
        for info in entries:
            name = info.filename
            if "/" in name or "\\" in name or name.startswith(".") or ".." in name or info.is_dir():
                issues.append(f"archive entry {name!r} is not a flat file name")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                issues.append(f"archive entry {name!r} is a symbolic link")
            if info.compress_type != zipfile.ZIP_STORED:
                issues.append(f"archive entry {name!r} is compressed")
            total += info.file_size
            if total > MAX_FIXTURE:
                issues.append("archive expands beyond the 4096-byte fixture cap")
                break
            issues += _text_issues(archive.read(info), f"archive entry {name!r}")
    return issues


def inert_issues(data: bytes, kind: str) -> List[str]:
    """Lint a fixture: tiny, well-formed, no interpreter line and no active markup."""
    issues = []
    if len(data) > MAX_FIXTURE:
        issues.append("exceeds the 4096-byte fixture cap")
    if data.startswith(b"#!"):
        issues.append("starts with an interpreter line")
    if kind == "text":
        issues += _text_issues(data, "text")
    elif kind == "png":
        issues += _png_issues(data)
    elif kind == "zip":
        issues += _zip_issues(data)
    else:
        issues.append("unknown fixture kind")
    return issues


class UploadLedger:
    def __init__(self, ctx):
        self.ctx = ctx
        self.db = ctx.store.db
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.config = validate_upload(ctx.campaign.raw.get("upload", {}))

    # ------------------------------------------------------------------ identity
    def _policy_hash(self) -> str:
        raw = self.ctx.campaign.raw
        return digest({"scope": [raw.get(k) for k in ("in_scope", "out_of_scope",
                                                       "excluded_bug_classes", "rules",
                                                       "program_url")],
                       "mode": self.ctx.policy.mode,
                       "methods": sorted(self.ctx.policy.allowed_methods),
                       "rules_reviewed": self.config["rules_reviewed"],
                       "grants": sorted(self.config["case_grants"])})

    def _sink(self, sink_id) -> Dict[str, Any]:
        if type(sink_id) is not int or sink_id < 1:
            raise ValueError("sink ID must be a positive integer")
        row = self.db.execute("SELECT * FROM upload_sinks WHERE id=?", (sink_id,)).fetchone()
        if not row:
            raise ValueError("unknown upload sink; run upload sync")
        sink = dict(row)
        self.ctx.scope.check(sink["url"])
        return sink

    def _context(self, context_id) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        if type(context_id) is not int or context_id < 1:
            raise ValueError("context ID must be a positive integer")
        row = self.db.execute("SELECT * FROM upload_contexts WHERE id=?", (context_id,)).fetchone()
        if not row:
            raise ValueError("unknown upload context; run upload sync")
        context = dict(row)
        return context, self._sink(context["sink_id"])

    def _event(self, event_id) -> Dict[str, Any]:
        if type(event_id) is not int or event_id < 1:
            raise ValueError("event ID must be a positive integer")
        row = self.db.execute("SELECT * FROM upload_events WHERE id=?", (event_id,)).fetchone()
        if not row:
            raise ValueError("unknown upload event")
        return dict(row)

    # ------------------------------------------------------------------ inventory
    def _upsert_sink(self, asset, url, method, field, transport, basis, surface=None, note=""):
        rank = {"declared": 0, "operator-declared": 1, "captured": 2}
        sources = sorted(set((asset.get("attrs") or {}).get("sources") or []))[:20]
        cur = self.db.execute(
            "INSERT OR IGNORE INTO upload_sinks(asset_id,url,method,field,transport,surface,basis,"
            "sources,note,created) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (asset["id"], url, method, field, transport, surface or _surface(url), basis,
             json.dumps(sources), note, now()))
        row = self.db.execute("SELECT id,basis FROM upload_sinks WHERE asset_id=? AND method=? AND "
                              "url=? AND field=? AND transport=?",
                              (asset["id"], method, url, field, transport)).fetchone()
        if not cur.rowcount and rank[basis] > rank.get(row["basis"], 0):
            self.db.execute("UPDATE upload_sinks SET basis=?,sources=? WHERE id=?",
                            (basis, json.dumps(sources), row["id"]))
        return row["id"], cur.rowcount

    def _upsert_context(self, sink_id, key, observations) -> int:
        account, role, tenant, workflow, capture_key = key
        ids = sorted(o["id"] for o in observations)
        basis = "captured" if observations else "declared"
        # Only this context's own captures reopen its evidence; unrelated captures do not.
        facets = digest({"observations": [(o["id"], o.get("params"), o.get("context"))
                                          for o in observations]})
        row = self.db.execute(
            "SELECT id,observation_ids,facets FROM upload_contexts WHERE sink_id=? AND account=? "
            "AND role=? AND tenant=? AND workflow=? AND capture_key=?",
            (sink_id, account, role, tenant, workflow, capture_key)).fetchone()
        if row:
            if (row["observation_ids"], row["facets"]) != (json.dumps(ids), facets):
                self.db.execute("UPDATE upload_contexts SET observation_ids=?,facets=?,basis=?,"
                                "updated=? WHERE id=?", (json.dumps(ids), facets, basis, now(), row["id"]))
            return 0
        self.db.execute(
            "INSERT INTO upload_contexts(sink_id,account,role,tenant,workflow,capture_key,basis,"
            "observation_ids,facets,updated) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (sink_id, account, role, tenant, workflow, capture_key, basis, json.dumps(ids),
             facets, now()))
        return 1

    def _sync_contexts(self, sink_id, observations, stats) -> None:
        groups = defaultdict(list)
        for o in observations:
            context = o.get("context") or {}
            labels = (o.get("account") or "unknown", context.get("role") or "unknown",
                      context.get("tenant") or "unknown", context.get("workflow_state") or "unknown")
            # Unlabelled captures are never pooled into one policy context.
            groups[(*labels, f"observation:{o['id']}" if "unknown" in labels else "")].append(o)
        if not groups:
            groups[("unknown", "unknown", "unknown", "unknown", "declared")] = []
        for key, group in list(groups.items())[:MAX_CONTEXTS]:
            stats["contexts"] += self._upsert_context(sink_id, key, group)
        stats["contexts_capped"] += max(0, len(groups) - MAX_CONTEXTS)

    def _sync_asset(self, asset, ops, stats) -> None:
        url = asset["value"]
        attrs = asset.get("attrs") or {}
        every = self.ctx.store.observations(asset["id"])
        observations = every[-500:]
        stats["observations_capped"] += max(0, len(every) - 500)
        seen = {(op["method"] or "UNKNOWN").upper() for op in ops} | \
            {str(m).upper() for m in attrs.get("methods") or []}
        known = seen - {"UNKNOWN"}
        methods = sorted(known & set(WRITE_METHODS)) if known else ["UNKNOWN"]
        declared_types = {t.lower() for t in attrs.get("content_types") or [] if isinstance(t, str)}
        for method in methods:
            matched = [o for o in observations if (o.get("method") or "UNKNOWN").upper() == method]
            names, types = set(), set(declared_types)
            for op in ops:
                if (op["method"] or "UNKNOWN").upper() == method:
                    names.update(p for p in op["attrs"].get("params") or [] if isinstance(p, str))
                    types.update(t.lower() for t in (op["attrs"].get("content_types") or []) +
                                 (op["attrs"].get("spec_content_types") or []) if isinstance(t, str))
            groups = defaultdict(list)
            # Each captured request names its own field and transport; two single-file
            # operations on one route are separate sinks, not a batch.
            for o in matched:
                params = o.get("params") or {}
                sent = sorted({n for n in (params.get("body") or []) + (params.get("query") or [])
                               if isinstance(n, str)})
                ctype = ((o.get("context") or {}).get("csrf_meta") or {}).get("content_type")
                seen_types = {ctype.lower()} if isinstance(ctype, str) and ctype else types
                fields = [n for n in sent if _file_field(n)][:20]
                transport = _transport(url, method, seen_types, fields, sent)
                for field in _sink_fields(transport, fields, sent):
                    groups[(field, transport)].append(o)
            if not matched and not self.db.execute(
                    "SELECT 1 FROM upload_sinks WHERE asset_id=? AND method=? AND "
                    "basis='operator-declared'", (asset["id"], method)).fetchone():
                names.update(p for p in attrs.get("params") or [] if isinstance(p, str))
                fields = sorted(n for n in names if _file_field(n))[:20]
                transport = _transport(url, method, types, fields, sorted(names))
                for field in _sink_fields(transport, fields, sorted(names)):
                    groups[(field, transport)] = []
            for (field, transport), group in groups.items():
                sink_id, added = self._upsert_sink(asset, url, method, field, transport,
                                                   "captured" if group else "declared")
                stats["sinks"] += added
                self._sync_contexts(sink_id, group, stats)

    def sync(self) -> Dict[str, Any]:
        """Idempotent inventory of captured/declared upload operations; no target requests."""
        ops = defaultdict(list)
        for op in self.ctx.store.operations():
            ops[op["endpoint_id"]].append(op)
        stats = Counter()
        assets = [a for a in self.ctx.store.assets("endpoint", in_scope=True)
                  if self.ctx.scope.is_in(a["value"]) and not is_inferred_only(a)
                  and _candidate(a, ops[a["id"]])]
        for asset in assets[:MAX_SINKS]:
            self._sync_asset(asset, ops[asset["id"]], stats)
        self.db.commit()
        return {"sinks_added": stats["sinks"], "contexts_added": stats["contexts"],
                "truncated": {"assets": max(0, len(assets) - MAX_SINKS),
                              "contexts": stats["contexts_capped"],
                              "observations": stats["observations_capped"]},
                "basis": "captured, declared and operator-declared upload operations; a sink is a "
                         "candidate, not an accepted, processed or executed file; no target requests",
                "executed": False}

    def declare(self, url, method, field, transport, surface="", note="") -> Dict[str, Any]:
        """Record an operation seen outside the multipart seed (signed storage, URL import...)."""
        if not isinstance(url, str) or len(url) > 2000:
            raise ValueError("url must be a bounded string")
        self.ctx.scope.check(url)
        method = (method or "").upper()
        if method not in WRITE_METHODS:
            raise ValueError("declared upload operations use POST, PUT or PATCH")
        if transport not in TRANSPORTS or surface and surface not in SURFACES:
            raise ValueError(f"transport must be one of {list(TRANSPORTS)}; surface one of {list(SURFACES)}")
        _safe_text(field, "field", 300)
        _safe_text(note, "note")
        if not field.strip() or not note.strip():
            raise ValueError("declare needs the field (or a (placeholder)) and where it was observed")
        params = [field] if not field.startswith("(") else []
        asset_id = self.ctx.add_endpoint(url, "upload-declared", method=method, params=params,
                                         extra={"basis": "operator-declared"})
        if asset_id is None:
            raise ValueError("operation not recorded (static path or unsupported URL)")
        asset = self.ctx.store.get_asset(asset_id)
        sink_id, added = self._upsert_sink(asset, asset["value"], method, field, transport,
                                           "operator-declared", surface or None, note)
        self._sync_contexts(sink_id, [], Counter())
        self.db.commit()
        return {"sink_id": sink_id, "added": bool(added), "url": asset["value"], "method": method,
                "field": field, "transport": transport,
                "basis": "operator-declared candidate; processing, storage and publication remain "
                         "unknown; no request was sent", "executed": False}

    def _destinations(self) -> List[Dict[str, Any]]:
        out = []
        for asset in self.ctx.store.assets("intel"):
            value = asset["value"]
            host = _host(value) if "://" in value else norm_host(value)
            if host and STORAGE_HOST_RE.search(host) and not self.ctx.scope.host_in(host):
                out.append({"value": value, "status": "outside the recorded scope; never requested",
                            "sources": ((asset.get("attrs") or {}).get("sources") or [])[:5]})
        return out[:50]

    # ------------------------------------------------------------------ gates
    def _callback_hosts(self) -> List[str]:
        hosts = self.config["callback_hosts"]
        if not hosts:
            ssrf = self.ctx.campaign.raw.get("ssrf", {})
            hosts = ssrf.get("callback_hosts", []) if isinstance(ssrf, dict) else []
        return validate_callback_hosts(hosts, "upload.callback_hosts")

    def _active_stop(self, host) -> Optional[Dict[str, Any]]:
        row = self.db.execute("SELECT * FROM upload_stops WHERE host=? AND cleared='' "
                              "ORDER BY id DESC LIMIT 1", (host,)).fetchone()
        return dict(row) if row else None

    def _usage(self) -> Dict[str, Any]:
        usage = {"requests": 0, "bytes": 0, "objects": 0, "hosts": Counter(), "channels": {}}
        for r in self.db.execute("SELECT e.channel,e.requests,e.bytes,e.objects,s.url FROM "
                                 "upload_events e JOIN upload_contexts c ON c.id=e.context_id "
                                 "JOIN upload_sinks s ON s.id=c.sink_id"):
            channel = usage["channels"].setdefault(r["channel"], {"requests": 0, "bytes": 0, "objects": 0})
            for key, column in (("requests", "requests"), ("bytes", "bytes"), ("objects", "objects")):
                channel[key] += r[column]
            if r["channel"] in LIVE_CHANNELS:
                usage["requests"] += r["requests"]
                usage["bytes"] += r["bytes"]
                usage["objects"] += r["objects"]
                usage["hosts"][_host(r["url"])] += r["requests"]
        return usage

    def _gates(self, sink) -> Dict[str, Any]:
        raw = self.ctx.campaign.raw
        host = _host(sink["url"])
        usage = self._usage()
        budget = self.config["budget"]
        accounts = {r["account"] for r in self.db.execute(
            "SELECT account,role,tenant,workflow FROM upload_contexts WHERE sink_id=? AND "
            "basis='captured'", (sink["id"],))
            if "unknown" not in (r["account"], r["role"], r["tenant"], r["workflow"])}
        return {"in_scope": self.ctx.scope.is_in(sink["url"]),
                "excluded": "file-upload" in (raw.get("excluded_bug_classes") or []),
                "stop": self._active_stop(host),
                "mode_ok": self.ctx.policy.mode != "passive",
                "method_ok": sink["method"] in self.ctx.policy.allowed_methods,
                "rules_ok": bool(str(raw.get("program_url") or "").strip()) and
                            bool(self.config["rules_reviewed"]),
                "budget": {"configured": budget["requests"],
                           "requests": budget["requests"] - usage["requests"],
                           "host": budget["per_host"] - usage["hosts"][host]},
                "callback_hosts": bool(self._callback_hosts()), "accounts": len(accounts)}

    def _readiness(self, context, sink, case, gates=None) -> Tuple[str, str]:
        gates = gates or self._gates(sink)
        spec = CASES[case]
        if not gates["in_scope"]:
            return "blocked", "sink is no longer in the campaign scope"
        if gates["excluded"]:
            return "blocked", "file-upload is excluded by the program rules"
        if spec["transports"] and sink["transport"] not in spec["transports"]:
            return "not-applicable", f"case needs transport {'/'.join(spec['transports'])}"
        if gates["stop"]:
            return "blocked", f"host stopped after {gates['stop']['stop_kind']}; review, then upload resume"
        callback_ready = {"transport", "callback"} <= self.config["case_grants"] and gates["callback_hosts"]
        if spec["mode"] == "review" or spec["mode"] == "review-unless-callback" and not callback_ready:
            return "review-only", "source/config review or owned lab only; record --channel review or lab"
        if not gates["mode_ok"]:
            return "blocked", "campaign mode is passive"
        if sink["method"] == "UNKNOWN":
            return "waiting-capture", "exact upload method not captured"
        if not gates["method_ok"]:
            return "blocked", f"policy.allowed_methods lacks {sink['method']}"
        if not gates["rules_ok"]:
            return "blocked", "record program_url and upload.rules_reviewed from the program's published rules"
        if context["basis"] != "captured":
            return "waiting-capture", "capture the real upload workflow for this context"
        if "unknown" in (context["account"], context["role"], context["tenant"], context["workflow"]):
            return "waiting-prerequisite", "label account/role/tenant/workflow on the capture"
        if spec["grant"] and spec["grant"] not in self.config["case_grants"]:
            return "blocked", f"upload.case_grants lacks {spec['grant']}"
        if spec["grant"] == "cross-account" and gates["accounts"] < 2:
            return "waiting-prerequisite", "two labelled test accounts must be captured on this sink"
        if gates["budget"]["configured"] == 0:
            return "blocked", "upload.budget allows no live traffic"
        if gates["budget"]["requests"] <= 0 or gates["budget"]["host"] <= 0:
            return "blocked", "upload budget exhausted for this host"
        return "ready", "inside the recorded scope, methods and budget; follow the program's published rules"

    # ------------------------------------------------------------------ evidence
    def _artifacts(self, items, roles) -> Dict[str, Tuple[str, bytes]]:
        if not isinstance(items, list) or len(items) > 12:
            raise ValueError("at most twelve artifacts")
        out = {}
        for item in items:
            if not isinstance(item, str):
                raise ValueError("artifacts must be ROLE=PATH strings")
            role, sep, path = item.partition("=")
            if not sep or role not in roles or role in out:
                raise ValueError(f"artifacts need unique ROLE=PATH with role in {list(roles)}")
            if (not path or len(path) > 300 or Path(path).is_absolute() or
                    ".." in Path(path).parts or SECRET_RE.search(path.encode())):
                raise ValueError("artifact must be a short campaign-relative redacted path")
            data = local_bytes(self.ctx.campaign.root, path)
            if SECRET_RE.search(data):
                raise ValueError("artifact appears to contain an unredacted secret")
            out[role] = (path, data)
        return out

    def _keep(self, data) -> List[Tuple[str, str, str, int, str]]:
        """Content-addressed copies under .recon/upload-evidence; never overwrite a different blob."""
        dest = self.ctx.campaign.state_dir / "upload-evidence"
        if dest.is_symlink() or self.ctx.campaign.state_dir.is_symlink():
            raise ValueError("refusing a symlinked evidence store")
        kept = []
        for role, (source, blob) in data.items():
            sha = _sha(blob)
            dest.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = dest / sha
            if path.is_symlink():
                raise ValueError("refusing a symlinked evidence file")
            if path.exists():
                if local_bytes(self.ctx.campaign.root, path) != blob:
                    raise ValueError("stored evidence changed")
            else:
                with path.open("xb") as stream:
                    stream.write(blob)
                path.chmod(0o600)
            kept.append((role, path.relative_to(self.ctx.campaign.root).as_posix(), sha,
                         len(blob), source))
        return kept

    def _stored(self, refs) -> Optional[Dict[str, bytes]]:
        blobs = {}
        for ref in refs:
            try:
                data = local_bytes(self.ctx.campaign.root, ref["path"])
            except (ValueError, OSError):
                return None
            if len(data) != ref["bytes"] or _sha(data) != ref["sha256"]:
                return None
            blobs[ref["role"]] = data
        return blobs

    def _event_blobs(self, event_id) -> Optional[Dict[str, bytes]]:
        return self._stored([dict(a) for a in self.db.execute(
            "SELECT role,path,sha256,bytes FROM upload_artifacts WHERE event_id=?", (event_id,))])

    def _has_callback(self, context_id, classes) -> bool:
        return bool(self.db.execute(
            "SELECT 1 FROM upload_callbacks cb JOIN upload_events e ON e.id=cb.event_id "
            f"WHERE e.context_id=? AND cb.classification IN ({','.join('?' for _ in classes)}) LIMIT 1",
            (context_id, *classes)).fetchone())

    def _fact_rule(self, fact, value, blobs, marker, control, state, route) -> None:
        if fact == "accepted":
            if "response" not in blobs:
                raise ValueError("accepted needs the upload response artifact")
        elif fact == "stored":
            sources = [blobs[r] for r in ("retrieval", "storage-log") if r in blobs]
            if not sources:
                raise ValueError("stored needs an owned retrieval or storage-log artifact")
            present = any(marker in blob for blob in sources)
            if (value == "yes") != present:
                raise ValueError(f"stored={value} contradicts the marker in retrieval/storage evidence")
        elif fact in ("reachable", "served"):
            if "retrieval" not in blobs:
                raise ValueError(f"{fact} needs an owned retrieval artifact")
            if (value == "yes") != (marker in blobs["retrieval"]):
                raise ValueError(f"{fact}={value} contradicts the marker in the retrieval artifact")
        elif fact == "processed":
            if value == "yes":
                worker = "worker-log" in blobs and marker in blobs["worker-log"]
                derived = "derivative" in blobs and marker in blobs["derivative"] and (
                    "original" not in blobs or _sha(blobs["derivative"]) != _sha(blobs["original"]))
                if not (worker or derived):
                    raise ValueError("processed=yes needs a worker log binding the marker or a "
                                     "distinct derivative carrying it")
            elif "worker-log" not in blobs or marker in blobs["worker-log"]:
                raise ValueError("processed=no needs a worker log without the marker")
        else:  # effect / executed
            if value != "yes":
                raise ValueError(f"{fact}=no cannot be proven by an artifact; leave it unknown")
            if state != "impact-demonstrated":
                raise ValueError(f"{fact}=yes is only recorded with impact-demonstrated")
            roles = ("effect", "replay", "control")
            if not set(roles) <= set(blobs):
                raise ValueError("an effect needs effect, replay and control artifacts")
            if not control:
                raise ValueError("an effect needs a distinct control marker")
            if len({_sha(blobs[r]) for r in roles}) != 3:
                raise ValueError("effect, replay and control artifacts must be distinct")
            if marker not in blobs["effect"] or marker not in blobs["replay"]:
                raise ValueError("effect and replay must carry the attempt marker")
            if fact == "executed":
                if "consumer-log" not in blobs or marker not in blobs["consumer-log"]:
                    raise ValueError("executed needs an attributable consumer log binding the marker")
                if route != "execution":
                    raise ValueError("executed evidence routes to the execution class")

    def _route_rule(self, route, case, facts, context_id) -> None:
        if route == "xss" and facts.get("served") != "yes":
            raise ValueError("xss route needs served=yes; same-origin rendering proof stays with hunt-xss")
        if route == "ssrf" and not self._has_callback(context_id, ("fetch-observed",)):
            raise ValueError("ssrf route needs a fetch-observed callback in this context")
        if route == "xxe" and not (case == "xml-document" and facts.get("processed") == "yes" and
                                   self._has_callback(context_id, ("fetch-observed", "resolution-observed"))):
            raise ValueError("xxe route needs xml-document processing plus correlated receiver evidence")
        if route == "file-read" and case not in ("inclusion-path", "archive-extraction"):
            raise ValueError("file-read route belongs to inclusion-path or archive-extraction evidence")
        if route == "ssti" and facts.get("processed") != "yes":
            raise ValueError("ssti route needs processed=yes; evaluation proof stays with hunt-ssti")
        if route in ("idor-bola", "access-control") and case not in ("published-authz", "intake-role"):
            raise ValueError("cross-account routes need published-authz or intake-role evidence")
        if route == "execution" and facts.get("executed") != "yes":
            raise ValueError("execution route needs executed=yes evidence")

    def _check_evidence(self, *, case, state, facts, blobs, marker, control_marker, route, layer,
                        request_ref, context_id, served_headers) -> None:
        m = marker.encode()
        control = control_marker.encode()
        if facts and not marker:
            raise ValueError("stage facts need the attempt marker")
        if "original" in blobs and marker and m not in blobs["original"]:
            raise ValueError("original must carry the owned marker")
        if "control" in blobs:
            if marker and m in blobs["control"]:
                raise ValueError("control must not carry the attempt marker")
            if control and control not in blobs["control"]:
                raise ValueError("control must carry its own control marker")
        for fact, value in facts.items():
            self._fact_rule(fact, value, blobs, m, control, state, route)
        if facts.get("executed") == "yes" and facts.get("effect") != "yes":
            raise ValueError("executed requires a demonstrated effect")
        if state == "accepted-inert" and (facts.get("accepted") != "yes" or
                                          "yes" in (facts.get("effect"), facts.get("executed"))):
            raise ValueError("accepted-inert needs accepted=yes and no effect/execution claim")
        if state == "rejected" and not (facts.get("accepted") == "no" or
                                        facts.get("accepted") == "yes" and layer in ("worker", "storage")):
            raise ValueError("rejected needs accepted=no, or a correlated worker/storage rejection "
                             "after acceptance")
        if state == "pending" and facts.get("accepted") != "yes":
            raise ValueError("pending needs accepted=yes with the response artifact")
        if state == "impact-demonstrated" and (facts.get("effect") != "yes" or not route):
            raise ValueError("impact-demonstrated needs effect=yes proof and a --route class")
        if state in ("review-candidate", "review-clear") and "review" not in blobs:
            raise ValueError("review states need a redacted review artifact")
        if route:
            self._route_rule(route, case, facts, context_id)
        if layer != "unconfirmed":
            log = blobs.get(f"{layer}-log")
            if log is None:
                raise ValueError(f"layer {layer} needs a {layer}-log artifact from the owner or owned lab")
            if not request_ref or request_ref.encode() not in log:
                raise ValueError("the layer log must contain the request reference")
        if case == "retrieval-policy" and facts.get("served") == "yes" and \
                not served_headers.get("content-type"):
            raise ValueError("a served retrieval needs its recorded Content-Type")

    def _event_issue(self, row, blobs) -> str:
        try:
            self._check_evidence(case=row["case_id"], state=row["state"],
                                 facts=json.loads(row["facts"]), blobs=blobs, marker=row["marker"],
                                 control_marker=row["control_marker"], route=row["route"],
                                 layer=row["layer"], request_ref=row["request_ref"],
                                 context_id=row["context_id"],
                                 served_headers=json.loads(row["served_headers"]))
        except ValueError as exc:
            return str(exc)[:200]
        return ""

    def _event_state(self, context, case) -> Tuple[str, Optional[int]]:
        row = self.db.execute("SELECT * FROM upload_events WHERE context_id=? AND case_id=? "
                              "ORDER BY id DESC LIMIT 1", (context["id"], case)).fetchone()
        if not row:
            return "open", None
        if row["policy_hash"] != self._policy_hash() or row["facet_hash"] != context["facets"]:
            return "stale", row["id"]
        blobs = self._event_blobs(row["id"])
        if blobs is None or self._event_issue(dict(row), blobs):
            return "stale", row["id"]
        return row["state"], row["id"]

    def _tool_refs(self, refs, sink, channel, state, requests) -> List[str]:
        refs = refs or []
        if not isinstance(refs, list) or len(refs) > 12 or len(set(refs)) != len(refs):
            raise ValueError("at most twelve unique tool references")
        natives = []
        for ref in refs:
            if not isinstance(ref, str) or not re.fullmatch(r"(?:burp|native):[A-Za-z0-9._:-]{1,100}", ref):
                raise ValueError("tool refs must be labelled burp: or native:")
            if ref.startswith("native:"):
                if channel != "native":
                    raise ValueError("native request IDs belong to --channel native")
                try:
                    request_id = int(ref.removeprefix("native:"))
                except ValueError as exc:
                    raise ValueError("native tool ref must name a stored request ID") from exc
                row = self.db.execute("SELECT method,url FROM requests WHERE id=? AND error IS NULL "
                                      "AND status IS NOT NULL", (request_id,)).fetchone()
                if not row or not self.ctx.scope.is_in(row["url"]) or \
                        origin_of(row["url"]) != origin_of(sink["url"]):
                    raise ValueError("native request ID is absent, failed, out of scope or from another origin")
                natives.append((row["method"], endpoint_key(row["url"])))
        if channel == "native" and state in TRAFFIC_STATES:
            if not any(m == sink["method"] and key == sink["url"] for m, key in natives):
                raise ValueError("native evidence needs a stored request for the exact upload operation")
            if requests != len(natives):
                raise ValueError("native request count must equal the cited stored request IDs")
        return refs

    def _charge(self, host, requests, size, objects) -> None:
        budget = self.config["budget"]
        used = self._usage()
        if (used["requests"] + requests > budget["requests"] or
                used["hosts"][host] + requests > budget["per_host"] or
                used["bytes"] + size > budget["bytes"] or used["objects"] + objects > budget["objects"]):
            raise ValueError(f"upload budget exhausted for {host}; stop and record --state blocked "
                             "--stop-trigger budget with --requests 0")

    def record(self, context_id, case, state, *, channel="browser", grant="", marker="",
               control_marker="", facts=None, artifacts=None, layer="unconfirmed", request_ref="",
               response_status=None, route="", stop_trigger="", served_headers=None, requests=0,
               bytes_sent=0, objects=0, object_ref="", tool_refs=None, root_key="",
               note="") -> Dict[str, Any]:
        context, sink = self._context(context_id)
        if case not in CASES or state not in STATES or channel not in CHANNELS:
            raise ValueError("unknown upload case, state or channel")
        spec = CASES[case]
        for label, text, limit in (("note", note, 2000), ("root key", root_key, 120),
                                   ("request reference", request_ref, 120),
                                   ("object reference", object_ref, 200)):
            _safe_text(text, label, limit)
        if layer not in LAYERS or route not in ("",) + ROUTES or stop_trigger not in ("",) + STOP_KINDS:
            raise ValueError("unknown layer, route or stop trigger")
        for label, value, high in (("requests", requests, 1000), ("bytes", bytes_sent, 50_000_000),
                                   ("objects", objects, 100)):
            if type(value) is not int or not 0 <= value <= high:
                raise ValueError(f"{label} must be 0..{high}")
        if response_status is not None and (type(response_status) is not int or
                                            not 100 <= response_status <= 599):
            raise ValueError("response status must be 100..599")
        declared = _parse_facts(facts)
        headers = _served(served_headers)
        if marker and not valid_marker(marker):
            raise ValueError("marker must be 16..96 characters of [A-Za-z0-9_-]")
        if control_marker and (not valid_marker(control_marker) or control_marker == marker):
            raise ValueError("control marker must be a distinct valid marker")
        if state in NOTE_STATES and not note.strip():
            raise ValueError(f"{state} needs a reason in --note")
        live = channel in LIVE_CHANNELS
        host = _host(sink["url"])
        gates = self._gates(sink)
        readiness, reason = self._readiness(context, sink, case, gates)
        if readiness == "not-applicable" and state != "n-a":
            raise ValueError(f"case not applicable: {reason}")
        if state == "n-a" and readiness != "not-applicable":
            raise ValueError("n-a needs a non-applicable transport, not a missing capture")
        if channel == "review":
            if requests or bytes_sent or objects:
                raise ValueError("review evidence sends nothing; requests, bytes and objects must be 0")
            if state not in REVIEW_STATES:
                raise ValueError(f"review channel records only {list(REVIEW_STATES)}")
        if state in ("review-candidate", "review-clear") and channel not in ("review", "lab"):
            raise ValueError("review states come from source/config review or an owned lab")
        if channel == "lab" and not _lab_host(host):
            raise ValueError("lab channel is only for loopback or reserved test hosts; "
                             "live targets use a live channel")
        if requests and gates["stop"] and channel != "review":
            raise ValueError(f"host {host} is stopped ({gates['stop']['stop_kind']}); review, then upload resume")
        if live:
            if readiness == "review-only":
                raise ValueError(f"case is review-only: {reason}")
            if state in TRAFFIC_STATES and readiness != "ready":
                raise ValueError(f"case is {readiness}: {reason}")
            if state in TRAFFIC_STATES and requests < 1:
                raise ValueError("live attempts need a declared request count")
            if case == "size-boundary" and bytes_sent > TINY_LIVE_BYTES:
                raise ValueError("live size-boundary attempts stay at or below 4096 bytes; "
                                 "review larger caps in configuration or an owned lab")
            if state in TRAFFIC_STATES and spec["grant"] and grant != spec["grant"]:
                raise ValueError(f"case requires --grant {spec['grant']}")
        if grant and (grant not in self.config["case_grants"] or grant != (spec["grant"] or "")):
            raise ValueError("grant does not match this case or the campaign's upload.case_grants")
        if state in TRAFFIC_STATES and not valid_marker(marker):
            raise ValueError("upload attempts need a test-owned marker")
        if response_status == 429 and stop_trigger != "rate-limit":
            raise ValueError("429 is a stop: record --state blocked --stop-trigger rate-limit")
        if response_status is not None and response_status >= 500 and stop_trigger != "server-error":
            raise ValueError("a 5xx is a stop: record --state blocked --stop-trigger server-error")
        if stop_trigger and state not in ("blocked", "inconclusive"):
            raise ValueError("a stop trigger is recorded with state blocked or inconclusive")
        refs = self._tool_refs(tool_refs, sink, channel, state, requests)
        data = self._artifacts(artifacts or [], ROLES)
        blobs = {role: blob for role, (_, blob) in data.items()}
        self._check_evidence(case=case, state=state, facts=declared, blobs=blobs, marker=marker,
                             control_marker=control_marker, route=route, layer=layer,
                             request_ref=request_ref, context_id=context_id, served_headers=headers)
        if live and (requests or bytes_sent or objects):
            self._charge(host, requests, bytes_sent, objects)
        deadline = _stamp(datetime.now(timezone.utc) + timedelta(days=self.config["retention_days"])) \
            if objects else ""
        kept = self._keep(data)
        cur = self.db.execute(
            "INSERT INTO upload_events(context_id,case_id,state,channel,grant,marker,control_marker,"
            "facts,layer,request_ref,response_status,route,stop_trigger,served_headers,requests,"
            "bytes,objects,object_ref,tool_refs,root_key,retention_deadline,policy_hash,facet_hash,"
            "note,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (context_id, case, state, channel, grant, marker, control_marker,
             json.dumps(declared, sort_keys=True), layer, request_ref, response_status, route,
             stop_trigger, json.dumps(headers, sort_keys=True), requests, bytes_sent, objects,
             object_ref, json.dumps(refs), root_key, deadline, self._policy_hash(),
             context["facets"], note, now()))
        for role, path, sha, size, source in kept:
            self.db.execute("INSERT INTO upload_artifacts VALUES(?,?,?,?,?,?)",
                            (cur.lastrowid, role, path, sha, size, source))
        if stop_trigger:
            self.db.execute("INSERT INTO upload_stops(host,stop_kind,event_id,created) VALUES(?,?,?,?)",
                            (host, stop_trigger, cur.lastrowid, now()))
        self.db.commit()
        original = data.get("original")
        known = bool(original and self.db.execute("SELECT 1 FROM upload_fixtures WHERE sha256=?",
                                                  (_sha(original[1]),)).fetchone())
        return {"event_id": cur.lastrowid, "context_id": context_id, "case": case, "state": state,
                "channel": channel, "facts": {f: declared.get(f, "unknown") for f in FACTS},
                "attribution": "layer-correlated" if layer != "unconfirmed" else "layer-unconfirmed",
                "layer": layer, "route": route or None,
                "eligible_for_review": state == "impact-demonstrated",
                "retention_deadline": deadline or None,
                "stopped_host": host if stop_trigger else None, "known_fixture": known,
                "artifacts": len(kept), "requests_declared": requests,
                "basis": "operator assertion with artifact-role, marker, control and hash checks; "
                         "not an independently confirmed finding; Burp/browser/scanner counts are "
                         "declared, not measured",
                "finding_promoted": False, "executed": False}

    def callback(self, event_id, kind, url, *, sent_at, observed_at, deadline, control_marker,
                 health="ok", job_id="", artifacts=None, note="") -> Dict[str, Any]:
        """Correlate receiver evidence to one attempt; contact never proves execution."""
        event = self._event(event_id)
        context, sink = self._context(event["context_id"])
        if "callback" not in self.config["case_grants"]:
            raise ValueError("callback evidence needs upload.case_grants to include callback")
        if event["state"] not in ("attempted", "accepted-inert", "pending", "inconclusive"):
            raise ValueError("callback evidence attaches to a recorded upload attempt")
        if kind not in CALLBACK_KINDS or health not in ("ok", "failed"):
            raise ValueError(f"kind must be one of {list(CALLBACK_KINDS)}; health ok or failed")
        _safe_text(note, "note")
        _safe_text(job_id, "job id", 120)
        _safe_text(url, "callback URL or host", 2000)
        marker = event["marker"]
        if not valid_marker(marker):
            raise ValueError("the attempt has no owned marker to correlate")
        if not valid_marker(control_marker) or control_marker == marker:
            raise ValueError("a distinct negative-control token is required")
        hosts = self._callback_hosts()
        if kind == "dns":
            host = norm_host((urlsplit(url).hostname or "") if "://" in url else url)
            if not re.fullmatch(r"[a-z0-9._-]{1,253}", host or "-"):
                raise ValueError("dns evidence names one receiver hostname")
            if not approved_callback_host(hosts, host):
                raise ValueError("receiver host has no upload.callback_hosts (or ssrf.callback_hosts) approval")
            if marker.lower() not in host:
                raise ValueError("callback must bind the attempt marker in the hostname")
            if host == _host(sink["url"]):
                raise ValueError("receiver must differ from the upload target")
        else:
            host = require_callback_url(url, hosts, "upload.callback_hosts", marker)
            if origin_of(url) == origin_of(sink["url"]):
                raise ValueError("receiver origin must differ from the upload target")
        start, seen, end = timestamp(sent_at), timestamp(observed_at), timestamp(deadline)
        if end <= start:
            raise ValueError("deadline must follow the attempt")
        if seen < start:
            raise ValueError("callback precedes the attempt; reversed order is not callback proof")
        data = self._artifacts(artifacts or [], CALLBACK_ROLES)
        blobs = {role: blob for role, (_, blob) in data.items()}
        if health == "failed":
            classification = "receiver-unhealthy"
        else:
            if "receiver-health" not in blobs:
                raise ValueError("record a receiver-health artifact before trusting the receiver")
            log = blobs.get("receiver-log")
            if log is None or marker.encode() not in log:
                raise ValueError("receiver log lacks the attempt marker; no callback proof")
            if control_marker.encode() in log:
                raise ValueError("the negative-control token reached the receiver; attribution fails")
            if seen > end:
                classification = "inconclusive-late"
            elif kind == "dns":
                classification = "resolution-observed"
            elif kind == "http":
                classification = "fetch-observed"
            else:
                worker = blobs.get("worker-log")
                if not job_id or worker is None or marker.encode() not in worker or \
                        job_id.encode() not in worker:
                    raise ValueError("worker-trace needs a worker log binding the marker and job ID")
                classification = "processor-attributed"
        kept = self._keep(data)
        refs = [{"role": r, "path": p, "sha256": s, "bytes": n} for r, p, s, n, _ in kept]
        cur = self.db.execute(
            "INSERT INTO upload_callbacks(event_id,kind,host,classification,sent_at,observed_at,"
            "deadline,control_marker,job_id,artifacts,note,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, kind, host, classification, sent_at, observed_at, deadline, control_marker,
             job_id, json.dumps(refs), note, now()))
        stopped = None
        if health == "failed":
            stopped = _host(sink["url"])
            self.db.execute("INSERT INTO upload_stops(host,stop_kind,event_id,created) VALUES(?,?,?,?)",
                            (stopped, "receiver-lost", event_id, now()))
        self.db.commit()
        return {"callback_id": cur.lastrowid, "event_id": event_id, "kind": kind, "host": host,
                "classification": classification, "proves_execution": False,
                "stopped_host": stopped,
                "basis": "approved receiver, marker/control and ordered-window checks; contact is "
                         "not code execution, an internal read or exfiltration", "executed": False}

    def _cleanups(self, event_id) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM upload_cleanup WHERE event_id=? ORDER BY id", (event_id,))]

    def cleanup(self, event_id, outcome, artifact="", note="") -> Dict[str, Any]:
        event = self._event(event_id)
        _, sink = self._context(event["context_id"])
        if outcome not in CLEANUP_OUTCOMES:
            raise ValueError(f"outcome must be one of {list(CLEANUP_OUTCOMES)}")
        if not event["objects"] and event["state"] not in TRAFFIC_STATES:
            raise ValueError("cleanup applies to an attempt that created or may have created objects")
        _safe_text(note, "note")
        blob, kept = None, []
        if artifact:
            data = self._artifacts([f"receipt={artifact}"], ("receipt",))
            blob = data["receipt"][1]
            kept = self._keep(data)
        if outcome in ("deleted", "aborted", "expired"):
            tokens = [t for t in (event["marker"], event["object_ref"]) if t]
            if blob is None or not any(t.encode() in blob for t in tokens):
                raise ValueError(f"{outcome} needs a receipt naming the attempt marker or object reference")
        if outcome == "retained-by-owner" and (blob is None or not note.strip()):
            raise ValueError("owner retention needs the owner's instruction as an artifact and a note")
        if outcome in ("failed", "unverified") and not note.strip():
            raise ValueError("explain the unresolved cleanup in --note")
        refs = [{"role": r, "path": p, "sha256": s, "bytes": n} for r, p, s, n, _ in kept]
        cur = self.db.execute("INSERT INTO upload_cleanup(event_id,outcome,artifacts,note,created) "
                              "VALUES(?,?,?,?,?)", (event_id, outcome, json.dumps(refs), note, now()))
        stopped = None
        if outcome in ("failed", "unverified"):
            stopped = _host(sink["url"])
            self.db.execute("INSERT INTO upload_stops(host,stop_kind,event_id,created) VALUES(?,?,?,?)",
                            (stopped, "cleanup-unresolved", event_id, now()))
        self.db.commit()
        return {"cleanup_id": cur.lastrowid, "event_id": event_id, "outcome": outcome,
                "resolved": outcome in CLEANUP_DONE, "stopped_host": stopped, "executed": False}

    def _pending_cleanup(self) -> List[Dict[str, Any]]:
        pending = []
        stamp = now()
        for r in self.db.execute("SELECT e.id,e.channel,e.objects,e.retention_deadline,s.url FROM "
                                 "upload_events e JOIN upload_contexts c ON c.id=e.context_id "
                                 "JOIN upload_sinks s ON s.id=c.sink_id WHERE e.objects>0 ORDER BY e.id"):
            done = self._cleanups(r["id"])
            latest = done[-1]["outcome"] if done else None
            if latest not in CLEANUP_DONE:
                pending.append({"event": r["id"], "host": _host(r["url"]), "channel": r["channel"],
                                "objects": r["objects"], "deadline": r["retention_deadline"],
                                "overdue": bool(r["retention_deadline"]) and stamp > r["retention_deadline"],
                                "outcome": latest})
        return pending

    def resume(self, host, note) -> Dict[str, Any]:
        host = norm_host(host or "")
        _safe_text(note, "note")
        if not host or not note.strip():
            raise ValueError("resume needs the stopped host and why it is safe to continue")
        active = [dict(r) for r in self.db.execute(
            "SELECT * FROM upload_stops WHERE host=? AND cleared='' ORDER BY id", (host,))]
        if not active:
            raise ValueError(f"host {host} is not stopped")
        if any(r["stop_kind"] == "cleanup-unresolved" for r in active) and any(
                p["host"] == host and p["outcome"] in ("failed", "unverified")
                for p in self._pending_cleanup()):
            raise ValueError("resolve the failed cleanup with a receipt before resuming")
        self.db.execute("UPDATE upload_stops SET cleared=?,clear_note=? WHERE host=? AND cleared=''",
                        (now(), note, host))
        self.db.commit()
        return {"host": host, "cleared": [r["stop_kind"] for r in active], "executed": False}

    # ------------------------------------------------------------------ fixtures
    def fixture(self, kind, size=None) -> Dict[str, Any]:
        """Write one inert marker fixture plus a distinct control into .recon/upload-fixtures."""
        marker, control = mint_marker("bvup"), mint_marker("bvctl")
        data, ext = fixture_bytes(kind, marker, size)
        control_data = control_bytes(control)
        issues = inert_issues(data, kind) + inert_issues(control_data, "text")
        if issues:
            raise ValueError("fixture failed the inert lint: " + "; ".join(issues))
        dest = self.ctx.campaign.state_dir / "upload-fixtures"
        if dest.is_symlink() or self.ctx.campaign.state_dir.is_symlink():
            raise ValueError("refusing a symlinked fixture store")
        dest.mkdir(parents=True, exist_ok=True, mode=0o700)
        paths = []
        for name, blob in ((f"{marker}.{ext}", data), (f"{control}.txt", control_data)):
            path = dest / name
            with path.open("xb") as stream:
                stream.write(blob)
            path.chmod(0o600)
            paths.append(path.relative_to(self.ctx.campaign.root).as_posix())
        self.db.execute("INSERT INTO upload_fixtures VALUES(?,?,?,?,?,?,?,?,?)",
                        (marker, control, kind, paths[0], _sha(data), len(data), paths[1],
                         _sha(control_data), now()))
        self.db.commit()
        return {"kind": kind, "marker": marker, "control_marker": control, "path": paths[0],
                "sha256": _sha(data), "bytes": len(data), "control_path": paths[1],
                "control_sha256": _sha(control_data), "inert": True,
                "note": "Inert marker fixture for owned baselines and labs. Upload only through the "
                        "campaign's approved path; cite it with --artifact original=PATH.",
                "executed": False}

    # ------------------------------------------------------------------ views
    def _card(self, sink) -> Dict[str, Any]:
        contexts = [dict(c) for c in self.db.execute(
            "SELECT * FROM upload_contexts WHERE sink_id=? ORDER BY id LIMIT ?", (sink["id"], MAX_CONTEXTS))]
        captured = any(c["basis"] == "captured" for c in contexts)
        gates = self._gates(sink)
        out = []
        for context in contexts:
            cases, lifecycle = [], []
            for case, spec in CASES.items():
                readiness, reason = self._readiness(context, sink, case, gates)
                state, event_id = self._event_state(context, case)
                if event_id is not None and state not in ("open", "stale"):
                    row = self.db.execute("SELECT facts,object_ref FROM upload_events WHERE id=?",
                                          (event_id,)).fetchone()
                    facts = json.loads(row["facts"])
                    lifecycle.append({"event_id": event_id, "case": case, "state": state,
                                      "object_ref": row["object_ref"] or None,
                                      "facts": {f: facts.get(f, "unknown") for f in FACTS}})
                cases.append({"case": case, "n": spec["n"], "grant": spec["grant"], "mode": spec["mode"],
                              "readiness": readiness, "reason": reason, "state": state,
                              "event_id": event_id, "priority": spec["priority"],
                              "compare": spec["compare"], "limit": spec["limit"]})
            out.append({"context_id": context["id"], "basis": context["basis"],
                        "superseded": context["basis"] != "captured" and captured,
                        "account": context["account"], "role": context["role"],
                        "tenant": context["tenant"], "workflow": context["workflow"],
                        "observations": json.loads(context["observation_ids"]),
                        "lifecycle": {"events": sorted(lifecycle, key=lambda e: e["event_id"]),
                                      "basis": "per-attempt stage facts; each object keeps its own "
                                               "stages; unknown is not no"},
                        "cases": sorted(cases, key=lambda x: (-x["priority"], x["n"]))})
        return {"sink_id": sink["id"], "asset_id": sink["asset_id"], "url": sink["url"],
                "method": sink["method"], "field": sink["field"], "transport": sink["transport"],
                "surface": sink["surface"], "basis": sink["basis"],
                "sources": json.loads(sink["sources"]), "contexts": out}

    def _budget_view(self) -> Dict[str, Any]:
        budget = self.config["budget"]
        usage = self._usage()
        return {"limits": dict(budget),
                "used": {k: usage[k] for k in ("requests", "bytes", "objects")},
                "per_host_used": dict(usage["hosts"]), "channels": usage["channels"],
                "basis": "one budget for browser, Burp, native and scanner upload traffic; non-native "
                         "counts are operator declarations the run owner reconciles; native counts "
                         "cite stored request IDs"}

    def _stopped(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT host,stop_kind,event_id,created FROM upload_stops WHERE cleared='' ORDER BY id")]

    def plan(self, sink_id=None, limit=25) -> Dict[str, Any]:
        self.sync()
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")
        if sink_id is not None:
            sinks = [self._sink(sink_id)]
        else:
            sinks = [dict(r) for r in self.db.execute("SELECT * FROM upload_sinks ORDER BY id")
                     if self.ctx.scope.is_in(r["url"])]
            sinks.sort(key=lambda s: (-int(s["transport"] in ("signed-storage", "url-import", "resumable")),
                                      -int(s["surface"] in ("document", "archive", "import", "preview",
                                                            "template")), s["id"]))
        total = len(sinks) if sink_id is None else 1
        sinks = sinks[:limit]
        return {"sinks": [self._card(s) for s in sinks], "total_sinks": total,
                "visible_sinks": len(sinks), "truncated_sinks": max(0, total - len(sinks)),
                "out_of_scope_destinations": self._destinations(),
                "grants": sorted(self.config["case_grants"]), "budget": self._budget_view(),
                "stopped_hosts": self._stopped(),
                "basis": "offline lifecycle worklist; a sink, transport label or readiness is a lead, "
                         "not authorization or proof", "executed": False}

    def verify(self) -> Dict[str, Any]:
        invalid, artifact_errors = [], []
        rows = self.db.execute("SELECT * FROM upload_events ORDER BY id").fetchall()
        for r in rows:
            try:
                context, _ = self._context(r["context_id"])
                blobs = self._event_blobs(r["id"])
                if blobs is None:
                    artifact_errors.append({"event": r["id"], "reason": "artifact missing/tampered"})
                    continue
                issue = self._event_issue(dict(r), blobs)
                if issue:
                    invalid.append({"event": r["id"], "reason": issue})
                if r["policy_hash"] != self._policy_hash() or r["facet_hash"] != context["facets"]:
                    invalid.append({"event": r["id"], "reason": "policy or context changed"})
            except (ValueError, OSError, OutOfScope) as exc:
                invalid.append({"event": r["id"], "reason": str(exc)[:160]})
        for table, label in (("upload_callbacks", "callback"), ("upload_cleanup", "cleanup")):
            for r in self.db.execute(f"SELECT id,artifacts FROM {table} ORDER BY id"):
                if self._stored(json.loads(r["artifacts"])) is None:
                    artifact_errors.append({label: r["id"], "reason": "artifact missing/tampered"})
        issues = artifact_errors + invalid
        return {"verified": not issues, "artifact_integrity": not artifact_errors,
                "events_checked": len(rows), "invalid": issues[:100],
                "truncated_invalid": max(0, len(issues) - 100), "executed": False}

    def status(self, limit=100) -> Dict[str, Any]:
        plan = self.plan(limit=limit)
        totals, open_cases, lifecycle, open_assets = Counter(), [], [], set()
        for card in plan["sinks"]:
            for context in card["contexts"]:
                if context["superseded"]:
                    continue
                for event in context["lifecycle"]["events"]:
                    lifecycle.append([card["sink_id"], context["context_id"], event["event_id"],
                                      event["case"], event["facts"]])
                for item in context["cases"]:
                    state = item["state"] if item["state"] != "open" else item["readiness"]
                    totals[state] += 1
                    if state not in CLOSED_STATES:
                        open_assets.add(card["asset_id"])
                        if len(open_cases) < 100:
                            open_cases.append([card["sink_id"], context["context_id"], item["case"], state])
        coarse = [[row["asset_id"], row["status"]] for row in self.ctx.store.coverage()
                  if row["bug_class"] == "file-upload" and
                  row["status"] in ("tested", "confirmed", "refuted", "n-a") and
                  row["asset_id"] in open_assets][:100]
        return {"totals": dict(totals), "open": open_cases, "lifecycle": lifecycle[:100],
                "coarse_conflicts": coarse, "budget": plan["budget"],
                "pending_cleanup": self._pending_cleanup()[:100],
                "stopped_hosts": plan["stopped_hosts"],
                "callbacks": [dict(r) for r in self.db.execute(
                    "SELECT id,event_id,kind,host,classification FROM upload_callbacks "
                    "ORDER BY id DESC LIMIT 30")],
                "root_groups": [dict(r) for r in self.db.execute(
                    "SELECT root_key,COUNT(*) AS events FROM upload_events WHERE root_key<>'' "
                    "GROUP BY root_key ORDER BY events DESC LIMIT 30")],
                "visible_sinks": plan["visible_sinks"], "total_sinks": plan["total_sinks"],
                "truncated_sinks": plan["truncated_sinks"], "integrity": self.verify(),
                "basis": "offline lifecycle state; a rejected contrast covers only that contrast; "
                         "coarse coverage never closes open cases; declared counts are not measured "
                         "traffic", "executed": False}


def report_rows(ctx) -> Dict[str, Any]:
    result = UploadLedger(ctx).status(limit=100)
    return {"totals": result["totals"], "open": result["open"][:30],
            "cleanup": [[p["event"], p["host"], p["objects"], p["deadline"] or "-",
                         "yes" if p["overdue"] else "no"] for p in result["pending_cleanup"][:30]],
            "stopped": [[s["host"], s["stop_kind"], s["event_id"]] for s in result["stopped_hosts"]],
            "coarse": result["coarse_conflicts"], "total": result["total_sinks"],
            "visible": result["visible_sinks"], "verified": result["integrity"]["verified"],
            "artifact_integrity": result["integrity"]["artifact_integrity"]}
