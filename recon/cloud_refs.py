"""Bounded, offline cloud-reference extraction and investigation priority.

No DNS, provider API, credential use, namespace guessing or request queue. A
reference is not proof of ownership, authorization, sensitive data or a finding.
The result deliberately contains no URL queries, signed bearer material or raw
credential-shaped matches; original bytes remain in the campaign-private source.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, List

from .extract import SECRET_PATTERNS

MAX_TEXT = 2_000_000
MAX_REFERENCES = 2000
_BUCKET = r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
_REGION = r"[a-z]{2}(?:-gov)?-[a-z]+-\d"
_UUID = r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"
_PATTERNS = (
    ("aws", "s3-bucket", re.compile(r"\bs3://(" + _BUCKET + r")(?:/[^\s\"'<>]*)?", re.I)),
    ("gcp", "gcs-bucket", re.compile(r"\bgs://(" + _BUCKET + r")(?:/[^\s\"'<>]*)?", re.I)),
    ("aws", "s3-bucket", re.compile(r"https?://(" + _BUCKET +
                                     r")\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?"
                                     r"(?:/[^\s\"'<>]*)?", re.I)),
    ("aws", "s3-bucket", re.compile(r"https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?/(" +
                                     _BUCKET + r")(?:/[^\s\"'<>]*)?", re.I)),
    ("azure", "blob-container", re.compile(
        r"https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9-]{3,63})"
        r"(?:/[^\s\"'<>]*)?", re.I)),
    ("gcp", "gcs-bucket", re.compile(r"https?://storage\.googleapis\.com/(" + _BUCKET +
                                     r")(?:/[^\s\"'<>]*)?", re.I)),
    ("aws", "arn", re.compile(r"\barn:(aws|aws-cn|aws-us-gov):([a-z][a-z0-9-]*):"
                               r"([a-z0-9-]*):([0-9]{0,12}):([A-Za-z0-9_./+=:@-]{1,160})")),
    ("azure", "resource-id", re.compile(
        r"(?<![\w/])(/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/([A-Za-z0-9_.()-]{1,90})/"
        r"providers/([A-Za-z0-9.]+/[A-Za-z0-9]+/[A-Za-z0-9_.()-]{1,90}))", re.I)),
    ("aws", "cognito-pool", re.compile(r"\bidentityPoolId\s*[:=]\s*['\"](" + _REGION +
                                      r":" + _UUID + r")['\"]", re.I)),
    ("aws", "rum-monitor", re.compile(r"\b(?:applicationId|monitorId)\s*[:=]\s*['\"](" +
                                     _UUID + r")['\"]", re.I)),
    ("gcp", "firebase-project", re.compile(
        r"\bprojectId\s*[:=]\s*['\"]([a-z][a-z0-9-]{4,62})['\"]", re.I)),
)
_SIGNATURE = re.compile(r"(?:^|[?&])(?:X-Amz-Signature|X-Goog-Signature|GoogleAccessId|sig)=", re.I)
_SENSITIVE_QUERY = re.compile(r"[?&](?:token|key|secret|credential|authorization)=", re.I)
_LABEL = re.compile(r"^[a-zA-Z0-9_.:/@+-]{1,200}$")


def _score(kind: str, before: str, historical: bool, signed: bool) -> tuple:
    """Heuristic priority only; never a severity, permission or testedness grade."""
    signal = []
    score = 1
    if kind in ("arn", "cognito-pool"):
        score += 3
        signal.append("identity-linked")
    if re.search(r"\b(?:upload|putobject|writ(e|able)|publish)\b", before, re.I):
        score += 2
        signal.append("writability-hint")
    if re.search(r"\b(?:deploy|lambda|function|build|artifact|package|runner)\b", before, re.I):
        score += 2
        signal.append("consumer-hint")
    if historical:
        score = max(0, score - 2)
        signal.append("historical")
    if signed:
        score = max(0, score - 1)
        signal.append("delegated-not-anonymous")
    if kind in ("firebase-project", "rum-monitor"):
        score = min(score, 2)
        signal.append("public-identifier")
    return score, sorted(set(signal))


def cloud_references(text: str, *, source_ref: str, media_type: str,
                     historical: bool = False) -> List[Dict]:
    """Return safe selectors and native resource IDs from ONE existing source.

    The source hash binds the *original* text, but callers must keep source bytes
    separately for verification. Spans refer to the original string, not an
    unescaped/reformatted derivative. Unknown scope stays unknown.
    """
    if (not isinstance(text, str) or len(text.encode("utf-8")) > MAX_TEXT or
            not isinstance(source_ref, str) or not _LABEL.fullmatch(source_ref) or
            not isinstance(media_type, str) or not _LABEL.fullmatch(media_type) or
            type(historical) is not bool or
            any(secret.search(source_ref) for secret in SECRET_PATTERNS.values())):
        raise ValueError("cloud references require bounded text and safe source/media labels")
    source_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    findings = []
    for provider, kind, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            # Do not include any token-shaped match or its URL query in the record.
            if any(secret.search(match.group(0)) for secret in SECRET_PATTERNS.values()):
                continue
            scope = {}
            if kind == "arn":
                partition, service, region, account, resource = match.groups()
                native = match.group(0)
                scope = {"partition": partition, "service": service, "region": region or None,
                         "account": account or None}
            elif kind == "resource-id":
                native = match.group(1)
                scope = {"subscription": match.group(2), "resource_group": match.group(3)}
            elif kind == "blob-container":
                native = match.group(1).lower() + "/" + match.group(2).lower()
                scope = {"account_name": match.group(1).lower(), "container": match.group(2).lower()}
            else:
                native = match.group(1).lower()
            # A signed query may appear directly after the reference, but neither
            # it nor object keys are exported (paths can themselves contain secrets).
            tail = text[match.start():min(len(text), match.end() + 16)]
            signed = bool(_SIGNATURE.search(tail) or _SENSITIVE_QUERY.search(tail))
            context = text[max(0, match.start() - 80):match.start()]
            score, signals = _score(kind, context, historical, signed)
            findings.append({"provider": provider, "resource_kind": kind,
                             "native_identifier": native, "scope": scope,
                             "ownership": "unknown", "source_ref": source_ref,
                             "source_sha256": source_sha, "media_type": media_type,
                             "selector": {"start": match.start(), "end": match.end()},
                             "historical": historical, "signed_context": signed,
                             "probe_priority": score, "triage_signals": signals})
            if len(findings) > MAX_REFERENCES:
                raise ValueError("cloud source exceeds reference cap; split with provenance")
    return sorted(findings, key=lambda r: (r["selector"]["start"], r["provider"],
                                            r["resource_kind"], r["native_identifier"]))
