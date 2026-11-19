"""Pure, offline DNS capture validation and conservative takeover review leads.

Capture schema (no other keys are accepted)::

    {"schema": 1, "source": "operator export reference", "observations": [
        {"name": "old.example.test", "record_type": "CNAME",
         "value": "unused.herokuapp.com", "result": "answer",
         "resolver": "192.0.2.53", "observed_at": "2026-11-16T10:00:00Z",
         "vantage": "recursive", "zone": "example.test"}
    ]}

There may be 0..2,000 observations. All eight observation fields above other
than ``zone`` are required. Optional fields are ``zone``, ``control_for``,
``certificate_not_before`` and ``certificate_not_after``. Times require an ISO
date/time with seconds and timezone. Values are strings of <=4,096 UTF-8 bytes:
A/AAAA addresses, CNAME/NS names, MX ``preference exchange`` (or ``0 .``), TXT
single-line text, or SOA ``mname rname serial refresh retry expire minimum``.
Non-answer results require an empty value. An empty *answer* is importable but
is a collection gap, never NODATA or NXDOMAIN. Names normalize to lowercase IDNA
with at most one terminal dot removed. No literal wildcards are accepted in
captures. TXT/CNAME owners and SPF references explicitly permit leading-underscore
service labels (e.g. ``selector._domainkey``); ordinary host names do not.

``parent-referral`` is NS-only and requires an enclosing ``zone``. A
``wildcard-control`` requires ``control_for`` referring to an actual captured
non-control name or explicitly captured zone. Its distinct sibling/direct-child
label must be at least eight characters with at least four different alphanumerics
and a letter. This is only a random-ish-label lint, not proof of randomness.

``classify`` returns one dict per non-control (name, record_type, value), with
``provider`` (str or None), ``confidence``, ``basis``/``gaps`` lists,
``referral_state``, ``wildcard_state``, ``address`` and ``dependencies``. Confidence
is candidate, potential, collection-gap or provider-stale; none means confirmed
or claimable. Comparisons require observations within 24 hours; address/control
comparisons also require the same resolver. Historical capture times are retained,
not certified as current DNS. Only the latest timestamp per owner/type/resolver/
vantage/zone/control binding participates; keep original bundles for history.
Out-of-scope names are valid intel, not authorization.

Provider records are exact dicts with ``provider``, ``status`` (unknown,
vulnerable, patched, edge-case), ``source`` (HTTPS URL) and ``checked`` (YYYY-MM-DD,
not future). They are sourced operator assertions, not vendor certifications.
Missing records and records older than 90 days are stale. No I/O is performed.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timezone
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

from .fingerprint import takeover_providers_for_cname


RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA")
RESULTS = ("answer", "nxdomain", "nodata", "servfail", "timeout", "refused")
VANTAGES = ("recursive", "parent-referral", "child-authoritative", "wildcard-control")
PROVIDER_STATUSES = ("unknown", "vulnerable", "patched", "edge-case")
MAX_OBSERVATIONS = 2000
_WINDOW_SECONDS = 24 * 60 * 60
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z")
_REQUIRED = {"name", "record_type", "value", "result", "resolver", "observed_at", "vantage"}
_OPTIONAL = {"zone", "control_for", "certificate_not_before", "certificate_not_after"}


def _text(value, label, limit, *, empty=False):
    if not isinstance(value, str) or (not value and not empty):
        raise ValueError(f"{label} must be {'a' if not empty else 'an optionally empty'} string")
    if len(value.encode("utf-8", errors="replace")) > limit or any(
            unicodedata.category(c).startswith("C") or c in "\u2028\u2029" for c in value):
        raise ValueError(f"{label} is too long or contains unsafe control characters")
    if value != value.strip():
        raise ValueError(f"{label} must not have surrounding whitespace")
    return value


def _label_characters(label):
    return bool(label) and not unicodedata.category(label[0]).startswith("M") and all(
        (c == "-" or unicodedata.category(c).startswith(("L", "M", "N"))) and
        not (0xFE00 <= ord(c) <= 0xFE0F or 0xE0100 <= ord(c) <= 0xE01EF) for c in label)


def _name(value, *, allow_wildcard=False, allow_underscore=False):
    value = _text(value, "DNS name", 1024)
    if any(c.isspace() or c in "/\\:@?#;|&`$<>\"'[](){}%" for c in value):
        raise ValueError("DNS name contains an unsafe delimiter")
    # Do not let IDNA silently reinterpret separators or delete format characters.
    if any(c in value for c in "\u3002\uff0e\uff61"):
        raise ValueError("DNS name requires literal dot separators")
    host = value[:-1] if value.endswith(".") else value
    labels = host.split(".")
    output = []
    for index, label in enumerate(labels):
        if label == "*" and index == 0 and allow_wildcard and len(labels) > 1:
            output.append(label)
            continue
        prefix = "_" if allow_underscore and label.startswith("_") else ""
        label = label[len(prefix):]
        if not _label_characters(label):
            raise ValueError("invalid character in DNS label")
        try:
            encoded = label.lower().encode("idna").decode("ascii").lower()
            if encoded.startswith("xn--"):
                # The encoder alone accepts malformed ASCII A-labels unchanged.
                decoded = encoded.encode("ascii").decode("idna")
                if not _label_characters(decoded) or \
                        decoded.encode("idna").decode("ascii") != encoded:
                    raise UnicodeError("noncanonical IDNA label")
        except UnicodeError as exc:
            raise ValueError("invalid IDNA DNS label") from exc
        if not _LABEL.fullmatch(encoded) or len(prefix + encoded) > 63:
            raise ValueError("invalid DNS label")
        output.append(prefix + encoded)
    host = ".".join(output)
    if len(host) > 253:
        raise ValueError("DNS name exceeds 253 octets")
    return host


def normalize_name(value, *, allow_wildcard=False):
    """Validate an LDH/IDNA DNS name; a leading ``*.`` needs explicit opt-in."""
    return _name(value, allow_wildcard=allow_wildcard)


def _timestamp(value):
    value = _text(value, "timestamp", 40)
    if not _TIME.fullmatch(value):
        raise ValueError("timestamp requires ISO date/time, seconds and timezone")
    if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise ValueError("invalid timezone offset")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    return result.astimezone(timezone.utc).isoformat()


def _as_date(at=None):
    if at is None:
        return datetime.now(timezone.utc).date()
    if isinstance(at, datetime):
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("at datetime requires a timezone")
        return at.astimezone(timezone.utc).date()
    if isinstance(at, date):
        return at
    if isinstance(at, str):
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", at):
            return date.fromisoformat(at)
        return datetime.fromisoformat(_timestamp(at)).date()
    raise ValueError("at must be a date or timezone-aware ISO timestamp")


def _uint(value, limit):
    if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) > limit:
        raise ValueError("invalid DNS unsigned integer")
    return str(int(value))


def _value(record_type, value, result):
    value = _text(value, "record value", 4096, empty=True)
    if result != "answer":
        if value:
            raise ValueError("non-answer observations require an empty value")
        return ""
    if not value:
        return ""
    if record_type in ("A", "AAAA"):
        if "%" in value:
            raise ValueError("scoped IP addresses are not DNS records")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("invalid address record") from exc
        if address.version != (4 if record_type == "A" else 6):
            raise ValueError("address family does not match record_type")
        return str(address)
    if record_type in ("CNAME", "NS"):
        return _name(value, allow_underscore=record_type == "CNAME")
    if record_type == "MX":
        parts = value.split(" ")
        if len(parts) != 2:
            raise ValueError("MX requires preference and exchange separated by one space")
        preference = _uint(parts[0], 65535)
        if parts[1] == ".":
            if preference != "0":
                raise ValueError("null MX requires preference zero")
            return "0 ."
        return preference + " " + normalize_name(parts[1])
    if record_type == "SOA":
        parts = value.split(" ")
        if len(parts) != 7:
            raise ValueError("SOA requires two names and five unsigned integers")
        return " ".join([normalize_name(p) for p in parts[:2]] +
                        [_uint(p, 2 ** 32 - 1) for p in parts[2:]])
    return value  # TXT is single-line inert text, not executable or interpreted markup.


def _encloses(zone, name):
    return name == zone or name.endswith("." + zone)


def _observation(data):
    if not isinstance(data, dict) or set(data) - (_REQUIRED | _OPTIONAL) or _REQUIRED - set(data):
        raise ValueError("observation has missing or unexpected fields")
    kind = data["record_type"]
    result, vantage = data["result"], data["vantage"]
    if kind not in RECORD_TYPES or result not in RESULTS or vantage not in VANTAGES:
        raise ValueError("invalid record_type, result or vantage")
    name = _name(data["name"], allow_underscore=kind in ("TXT", "CNAME"))
    resolver = _text(data["resolver"], "resolver", 253)
    try:
        if "%" in resolver:
            raise ValueError("scoped resolver address")
        resolver = str(ipaddress.ip_address(resolver))
    except ValueError:
        resolver = normalize_name(resolver)
    out = {"name": name, "record_type": kind, "value": _value(kind, data["value"], result),
           "result": result, "resolver": resolver, "observed_at": _timestamp(data["observed_at"]),
           "vantage": vantage}
    if "zone" in data:
        out["zone"] = normalize_name(data["zone"])
        if not _encloses(out["zone"], name):
            raise ValueError("zone must enclose the observed name on a label boundary")
    if vantage == "parent-referral" and (kind != "NS" or "zone" not in out):
        raise ValueError("parent-referral requires an NS observation and enclosing zone")
    if vantage == "wildcard-control":
        if "control_for" not in data:
            raise ValueError("wildcard-control requires control_for")
        out["control_for"] = _name(data["control_for"], allow_underscore=kind in ("TXT", "CNAME"))
    elif "control_for" in data:
        raise ValueError("control_for is only valid for wildcard-control")
    for field in ("certificate_not_before", "certificate_not_after"):
        if field in data:
            out[field] = _timestamp(data[field])
    if all(k in out for k in ("certificate_not_before", "certificate_not_after")):
        if out["certificate_not_before"] > out["certificate_not_after"]:
            raise ValueError("certificate validity interval is reversed")
    return out


def validate_capture(data):
    """Return a normalized copy of the exact schema-1 bundle, or raise ValueError."""
    if not isinstance(data, dict) or set(data) != {"schema", "source", "observations"}:
        raise ValueError("capture requires exactly schema, source and observations")
    if type(data["schema"]) is not int or data["schema"] != 1:
        raise ValueError("capture schema must be integer 1")
    source = _text(data["source"], "source", 1024)
    raw = data["observations"]
    if not isinstance(raw, list) or len(raw) > MAX_OBSERVATIONS:
        raise ValueError("observations must be a list of at most 2000 records")
    observations = [_observation(row) for row in raw]
    actual = {r["name"] for r in observations if r["vantage"] != "wildcard-control"}
    zones = {r["zone"] for r in observations if "zone" in r and r["vantage"] != "wildcard-control"}
    for row in observations:
        if row["vantage"] != "wildcard-control":
            continue
        target, name = row["control_for"], row["name"]
        if target not in actual | zones or name in actual or name == target:
            raise ValueError("control must be distinct and tied to an actual name or zone")
        suffixes = set()
        if target in zones:
            suffixes.add(target)
        if target in actual and "." in target:
            suffixes.add(target.split(".", 1)[1])
        labels = [name[:-(len(suffix) + 1)] for suffix in suffixes
                  if name.endswith("." + suffix)]
        if not any("." not in label and len(label) >= 8 and
                   len(set(c for c in label if c.isalnum())) >= 4 and
                   any(c.isalpha() for c in label) for label in labels):
            raise ValueError("control must have a random-ish sibling or direct-child label")
    return {"schema": 1, "source": source, "observations": observations}


def validate_provider_records(status_records, at=None):
    """Validate bounded, sourced provider-status assertions without fetching sources."""
    today = _as_date(at)
    if not isinstance(status_records, list) or len(status_records) > MAX_OBSERVATIONS:
        raise ValueError("provider status records must be a list of at most 2000 records")
    out = []
    for row in status_records:
        if not isinstance(row, dict) or set(row) != {"provider", "status", "source", "checked"}:
            raise ValueError("provider record has missing or unexpected fields")
        provider = _provider_name(row["provider"])
        if row["status"] not in PROVIDER_STATUSES:
            raise ValueError("invalid provider status")
        source = _text(row["source"], "provider source", 2048)
        if any(c.isspace() or c in "\\<>\"`|" for c in source):
            raise ValueError("unsafe provider source URL")
        try:
            url = urlsplit(source)
            if url.scheme != "https" or not url.hostname or url.username is not None or \
                    url.password is not None or url.fragment or url.port == 0:
                raise ValueError("provider source must be an HTTPS URL without userinfo or fragment")
            if ":" in url.hostname:
                if "%" in url.hostname:
                    raise ValueError("scoped source address")
                host = "[" + str(ipaddress.IPv6Address(url.hostname)) + "]"
            else:
                host = normalize_name(url.hostname)
            port = url.port
        except (ValueError, UnicodeError) as exc:
            raise ValueError("invalid provider source HTTPS URL") from exc
        checked = row["checked"]
        if not isinstance(checked, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", checked):
            raise ValueError("provider checked requires YYYY-MM-DD")
        checked_date = date.fromisoformat(checked)
        if checked_date > today:
            raise ValueError("provider checked date must not be future")
        out.append({"provider": provider, "status": row["status"],
                    "source": urlunsplit(("https", host + (f":{port}" if port else ""),
                                          url.path, url.query, "")), "checked": checked})
    return out


def _provider_name(provider):
    provider = _text(provider, "provider", 80).lower()
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", provider):
        raise ValueError("invalid provider identifier")
    return provider


def _provider_info(provider, records, today):
    matching = [r for r in records if r["provider"] == provider]
    if not matching:
        return {"provider": provider, "status": "unknown", "source": None, "checked": None,
                "stale": True, "age_days": None, "conflict": False,
                "basis": ["provider-status-missing", "provider-status-is-an-assertion"]}
    checked = max(r["checked"] for r in matching)
    newest = [r for r in matching if r["checked"] == checked]
    conflict = len({r["status"] for r in newest}) > 1
    age = (today - date.fromisoformat(checked)).days
    basis = ["provider-status-is-an-assertion"]
    if conflict:
        basis.append("provider-status-conflicting")
    if age > 90:
        basis.append("provider-status-stale")
    return {"provider": provider, "status": "unknown" if conflict else newest[0]["status"],
            "source": None if conflict else sorted(r["source"] for r in newest)[0],
            "checked": checked, "stale": age > 90, "age_days": age, "conflict": conflict,
            "basis": basis}


def provider_info(provider, status_records, at=None):
    """Summarize the latest dated assertion; stale/unknown never certifies a vendor."""
    today = _as_date(at)
    name = None if provider is None or provider == "" else _provider_name(provider)
    return _provider_info(name, validate_provider_records(status_records, today), today)


def _near(row, anchor, *, same_resolver=True):
    return (not same_resolver or row["resolver"] == anchor["resolver"]) and abs(
        (datetime.fromisoformat(row["observed_at"]) -
         datetime.fromisoformat(anchor["observed_at"])).total_seconds()) <= _WINDOW_SECONDS


def _rr_state(rows):
    if not rows:
        return "missing"
    states = {"answer" if r["value"] else "empty" if r["result"] == "answer" else r["result"]
              for r in rows}
    return next(iter(states)) if len(states) == 1 else "inconsistent"


def _latest(rows):
    """Project current evidence only; raw captures remain the caller's history."""
    groups = defaultdict(list)
    for row in rows:
        key = tuple(row.get(field) for field in ("name", "record_type", "resolver", "vantage", "zone", "control_for"))
        groups[key].append(row)
    output = []
    for group in groups.values():
        newest = max(row["observed_at"] for row in group)
        output.extend(row for row in group if row["observed_at"] == newest)
    return output


def _address(name, rows, anchor):
    selected = [r for r in rows if r["name"] == name and _near(r, anchor) and
                r["vantage"] not in ("wildcard-control", "parent-referral")]
    families = {kind: _rr_state([r for r in selected if r["record_type"] == kind])
                for kind in ("A", "AAAA")}
    states = set(families.values())
    nonexistent = any(r["result"] == "nxdomain" for r in selected)
    exists = any(r["result"] in ("answer", "nodata") for r in selected)
    if "inconsistent" in states or (nonexistent and exists):
        state = "inconsistent"
    elif "answer" in states:
        state = "resolved"
    elif states & {"empty", "timeout", "servfail", "refused"}:
        state = "unknown"
    elif nonexistent:
        state = "nxdomain"  # NXDOMAIN is name-wide, unlike family-specific NODATA.
    elif states == {"nodata"}:
        state = "no-address-data"
    else:
        state = "unknown"
    return {"name": name, "state": state, **families}


def _wildcard(anchor, rows):
    controls = [r for r in rows if r["vantage"] == "wildcard-control" and
                r["record_type"] == anchor["record_type"] and _near(r, anchor) and
                r["name"].partition(".")[2] == anchor["name"].partition(".")[2] and
                (r["control_for"] == anchor["name"] or
                 r["control_for"] == anchor["name"].partition(".")[2])]
    state = _rr_state(controls)
    if state == "missing":
        return "untested"
    if state in ("nxdomain", "nodata"):
        return "negative"
    if state == "answer":
        return "matching" if any(r["value"] == anchor["value"] for r in controls) else "answering"
    return "inconsistent" if state == "inconsistent" else "unknown"


def _referral(anchor, rows):
    if anchor["record_type"] != "NS":
        return "not-applicable"
    zone = anchor.get("zone", anchor["name"])
    parent = [r for r in rows if r["record_type"] == "NS" and r["vantage"] == "parent-referral"
              and r["zone"] == zone and _near(r, anchor, same_resolver=False)]
    child = [r for r in rows if r["record_type"] == "NS" and r["vantage"] == "child-authoritative"
             and r["name"] == zone and _near(r, anchor, same_resolver=False)]
    if not parent:
        return "recursive-only" if anchor["vantage"] == "recursive" else "parent-missing"
    if not child:
        return "child-missing"
    if _rr_state(parent) != "answer" or _rr_state(child) != "answer":
        return "unknown"
    # Do not union disagreeing answers from different servers/times into a match.
    def rrsets(items):
        groups = defaultdict(set)
        for row in items:
            groups[(row["resolver"], row["observed_at"])].add(row["value"])
        return {frozenset(values) for values in groups.values()}
    parents, children = rrsets(parent), rrsets(child)
    if len(parents) != 1 or len(children) != 1:
        return "inconsistent"
    return "match" if parents == children else "mismatch"


def _dependencies(anchor, rows):
    """Extract literal DNS dependencies only; never expand SPF macros or DKIM selectors."""
    kind, value = anchor["record_type"], anchor["value"]
    references, gaps = [], []
    if kind == "MX" and value and value != "0 .":
        references.append(("mx", value.split(" ")[1], "address"))
    elif kind == "MX" and anchor["result"] == "nodata":
        references.append(("mx-implicit-address-fallback", anchor["name"], "address"))
    if kind == "CNAME" and "_domainkey" in anchor["name"].split(".") and value:
        references.append(("dkim", value, "TXT"))
    if kind == "TXT" and value:
        text = value[1:-1] if value.startswith('"') and value.endswith('"') else value
        if text.lower().startswith("v=spf1 "):
            for term in text.split()[1:]:
                term = term.lstrip("+-~?")
                match = re.fullmatch(r"(include|exists|a|mx|ptr):(.+)|(?:redirect|exp)=(.+)", term, re.I)
                if not match:
                    implicit = re.fullmatch(r"(a|mx|ptr)(?:/[0-9/]+)?", term, re.I)
                    if not implicit:
                        continue
                    mechanism, target = implicit.group(1).lower(), anchor["name"]
                else:
                    mechanism = (match.group(1) or term.split("=", 1)[0]).lower()
                    target = match.group(2) or match.group(3)
                if mechanism in ("a", "mx"):
                    target = target.split("/", 1)[0]
                if "%" in target:
                    gaps.append("spf-macro-reference-unresolved")
                    continue
                try:
                    target = _name(target, allow_underscore=True)
                except ValueError:
                    gaps.append("invalid-spf-reference")
                    continue
                rrtype = "address" if mechanism == "a" else "A" if mechanism == "exists" else "MX" if mechanism == "mx" else \
                    "PTR" if mechanism == "ptr" else "TXT"
                references.append(("spf-" + mechanism, target, rrtype))
    dependencies = []
    for dependency, name, rrtype in sorted(set(references)):
        if rrtype == "address":
            state = _address(name, rows, anchor)["state"]
        else:
            state = _rr_state([r for r in rows if r["name"] == name and r["record_type"] == rrtype and
                               r["vantage"] not in ("wildcard-control", "parent-referral") and _near(r, anchor)])
        dependencies.append({"kind": dependency, "name": name, "record_type": rrtype, "state": state,
                             "gaps": ["dependency-control-and-claimability-not-established"] +
                             (["dependency-capture-missing-or-unresolved"] if state not in
                              ("answer", "resolved", "nxdomain", "nodata", "no-address-data") else [])})
    return dependencies, gaps


def classify(observations, provider_status=None, at=None):
    """Classify validated or raw observation dicts, without I/O or finding promotion.

    Pass ``validate_capture(bundle)["observations"]`` (not the bundle itself).
    Validation is repeated so callers cannot bypass control or schema checks.
    ``provider_status`` is the list accepted by ``validate_provider_records``.
    """
    rows = validate_capture({"schema": 1, "source": "offline-classifier", "observations": observations})["observations"]
    rows = _latest(rows)
    today = _as_date(at)
    records = validate_provider_records([] if provider_status is None else provider_status, today)
    groups = defaultdict(list)
    for row in rows:
        if row["vantage"] != "wildcard-control":
            groups[(row["name"], row["record_type"], row["value"])].append(row)
    output = []
    for (name, kind, value), group in sorted(groups.items()):
        anchor = max(group, key=lambda r: (r["observed_at"], r["vantage"], r["resolver"]))
        result = _rr_state(group)
        providers = takeover_providers_for_cname(value) if kind == "CNAME" and value else []
        info = _provider_info(providers[0], records, today) if providers else None
        wildcards = {_wildcard(item, rows) for item in group}
        referrals = {_referral(item, rows) for item in group}
        wildcard = next(iter(wildcards)) if len(wildcards) == 1 else "inconsistent"
        referral = next(iter(referrals)) if len(referrals) == 1 else "inconsistent"
        addresses = [_address(value if kind == "CNAME" and value else name, rows, item) for item in group]
        address = {"name": addresses[0]["name"]}
        for field in ("state", "A", "AAAA"):
            states = {item[field] for item in addresses}
            address[field] = next(iter(states)) if len(states) == 1 else "inconsistent"
        dependencies, gaps = _dependencies(anchor, rows)
        basis = ["operator-capture-not-live-verification", "claimability-not-established"]
        confidence = "candidate"
        if result != "answer":
            basis.append("dns-" + result)
            gaps.append("record-answer-missing-or-unresolved")
            confidence = "collection-gap"
        if kind == "CNAME" and value:
            basis.append("cname-provider-suffix" if providers else "cname-unrecognized-provider")
            if dependencies:  # DKIM is a TXT dependency, not an address-backed web resource.
                basis.append("dkim-reference-dependency-only")
                gaps.append("mail-control-and-claimability-not-established")
                confidence = "collection-gap"
            elif address["state"] in ("nxdomain", "no-address-data"):
                basis.append("cname-target-" + address["state"])
                confidence = "potential"
            elif address["state"] in ("unknown", "inconsistent"):
                gaps.append("cname-target-address-" + address["state"])
                confidence = "collection-gap"
            else:
                basis.append("cname-target-has-address-data")
            if wildcard != "negative":
                gaps.append("wildcard-" + wildcard)
                confidence = "collection-gap"
            if info:
                basis.extend(info["basis"])
                basis.append("provider-reported-" + info["status"])
                if info["status"] == "patched":
                    basis.append("provider-reported-patched-not-a-capture-refutation")
                    if confidence == "potential":
                        confidence = "candidate"
                if info["conflict"] or info["status"] == "unknown":
                    gaps.append("provider-status-unknown-or-conflicting")
                    if confidence == "potential" and (info["conflict"] or not info["stale"]):
                        confidence = "collection-gap"
                if info["stale"] and confidence != "collection-gap":
                    confidence = "provider-stale"
            else:
                gaps.append("provider-requirements-unknown")
                if confidence == "potential":
                    confidence = "collection-gap"
        elif kind == "NS":
            basis.append("ns-referral-" + referral)
            basis.append("ns-mismatch-is-not-claimability")
            if referral == "mismatch" and wildcard == "negative":
                confidence = "potential"
            else:
                confidence = "collection-gap"
                if referral not in ("match", "mismatch"):
                    gaps.append("parent-and-child-referral-comparison-incomplete")
                if wildcard != "negative":
                    gaps.append("wildcard-" + wildcard)
        elif kind in ("MX", "TXT"):
            basis.append("mail-reference-dependency-only" if dependencies else "dns-text-or-mail-observation-only")
            gaps.append("mail-control-and-claimability-not-established")
            confidence = "collection-gap"
        elif kind in ("A", "AAAA"):
            basis.append("address-family-" + kind.lower() + "-only")
            gaps.append("recyclable-address-ownership-not-established")
            confidence = "collection-gap"
        elif kind == "SOA":
            basis.append("soa-observation-only")
            confidence = "collection-gap"
        if result != "answer":
            confidence = "collection-gap"
        output.append({"name": name, "record_type": kind, "value": value, "provider": providers[0] if providers else None,
                       "providers": providers, "provider_info": info, "confidence": confidence,
                       "basis": sorted(set(basis)), "gaps": sorted(set(gaps)), "referral_state": referral,
                       "wildcard_state": wildcard, "address": address, "dependencies": dependencies,
                       "observed_at": anchor["observed_at"], "resolver": anchor["resolver"],
                       "results": sorted({r["result"] for r in group}),
                       "resolvers": sorted({r["resolver"] for r in group}),
                       "vantages": sorted({r["vantage"] for r in group})})
    return output
