"""What a primitive actually yields: the measurement that sets severity.

**Reach is not impact.** Proving that a request arrived at `169.254.169.254`, or that an
environment read executes, establishes a *primitive*. It says nothing about whether what
comes back is a live cloud credential or a page of build flags. Two findings with an
identical primitive are a low and a critical depending on that answer, so this module
requires the answer before `impact-proven` and derives the severity ceiling from it
(operator decision, 2026-11-22, superseding the earlier "severity follows reach" rule in
`plans/artex-adoption.md` §5.5).

Four questions, which together are the measurement:

1. **What is the data about?** Every characterised item is counted under one of
   `CLASSES`, and `subjects` says in words what it is ("STS credentials for the
   `prod-api-task` role", "support tickets of other tenants").
2. **Is it valuable or noise?** Each class carries a `SENSITIVITY` tier. Build flags and
   generated identifiers are `none`; a signing key is `credential`.
3. **How much is reachable from here?** `reachable`, with an `enumeration` basis saying
   whether that is the complete set or a lower bound from a bounded sample.
4. **How much was actually verified?** `sampled`, and the class counts must add up to
   it, so a claim about 10,000 records cannot rest on having looked at none of them.

Severity then follows the data, not the primitive: one live credential is critical, a
hundred other-tenant records are critical, two are high, one is medium, internal
structure is medium, and noise is low. A proven primitive with the data left unmeasured
is capped at medium — it is a real finding, just not an evidenced impact claim.

**Values are never stored.** An item is recorded as its field name plus a redacted
fingerprint: a prefix of at most `MAX_PREFIX` characters and a salted SHA-256. That is
enough to prove two observations saw the same secret, and enough for a report, without
copying a live credential for a system you do not own into local files or a model's
context. A measurement carrying a `value`-shaped key, or an over-long prefix, is
refused — the redaction is structural, not a convention to remember.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

__all__ = ["CLASSES", "SENSITIVITY", "TIERS", "ENUMERATIONS", "MAX_PREFIX",
           "validate", "ceiling", "tier_of", "summarise", "UNMEASURED_CEILING"]

#: Ordered least to most serious; `tier_of` and `ceiling` rely on the order.
TIERS: Tuple[str, ...] = ("none", "internal", "sensitive", "credential")

#: What a characterised item is, and how serious that kind of data is.
CLASSES: Dict[str, Tuple[str, str]] = {
    "noise": ("none", "generated, random or meaningless values an attacker gains nothing from"),
    "public-config": ("none", "values already public or published by design"),
    "build-metadata": ("none", "versions, commit ids, build flags, feature toggles"),
    "internal-hostname": ("internal", "internal host, service or network address"),
    "internal-path": ("internal", "filesystem path, bucket, queue or topic name"),
    "software-inventory": ("internal", "installed packages, versions, dependency lists"),
    "account-identifier": ("internal", "cloud account, project, tenant or role *name* only"),
    "pii": ("sensitive", "personal data of a real person"),
    "business-record": ("sensitive", "another tenant's or user's business data"),
    "private-content": ("sensitive", "private messages, tickets, documents or files"),
    "session-token": ("credential", "session cookie or bearer token for an account"),
    "api-key": ("credential", "API key or service secret"),
    "cloud-credential": ("credential", "cloud role credentials, access keys, STS tokens"),
    "database-credential": ("credential", "DSN or user/password for a datastore"),
    "signing-key": ("credential", "private key, JWT signing secret or HMAC secret"),
}

SENSITIVITY: Dict[str, str] = {name: tier for name, (tier, _) in CLASSES.items()}

#: `complete` = the whole reachable set was listed. `bounded-sample` = `reachable` is a
#: lower bound, because the enumeration was deliberately capped (program rules, budget,
#: politeness). Either is honest; conflating them is not.
ENUMERATIONS: Tuple[str, ...] = ("complete", "bounded-sample")

#: A proven primitive whose data was never characterised. A real finding, not an
#: evidenced impact claim.
UNMEASURED_CEILING = "medium"

MAX_PREFIX = 4
MAX_SUBJECTS = 20
MAX_SUBJECT_LEN = 200
MAX_FINGERPRINTS = 50
MAX_FIELD_LEN = 120
MAX_REACHABLE = 100_000_000

#: Counts at which a tier's ceiling rises. One other-tenant record may be your own test
#: object; a hundred is a breach.
SENSITIVE_HIGH = 2
SENSITIVE_CRITICAL = 100

_FIELD = re.compile(r"^[\w.:/\[\]-]{1,%d}$" % MAX_FIELD_LEN)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
#: Keys that would mean a raw value was pasted in. Refused outright.
_VALUE_KEYS = ("value", "secret", "plaintext", "raw", "password", "token_value", "cleartext")


class MeasurementError(ValueError):
    """The measurement is missing, inconsistent, or carries a raw value."""


def tier_of(classes: Dict[str, int]) -> str:
    """The most serious tier present, or `none` for an empty classification."""
    present = [SENSITIVITY[name] for name in classes]
    return max(present, key=TIERS.index) if present else "none"


def _reject_values(obj: Any, path: str = "data_impact") -> None:
    """Refuse a measurement that carries a raw secret anywhere inside it."""
    if isinstance(obj, dict):
        for key, item in obj.items():
            lowered = str(key).lower()
            if any(bad == lowered for bad in _VALUE_KEYS):
                raise MeasurementError(
                    f"{path}.{key} looks like a raw value; record a field name and a "
                    f"redacted fingerprint (prefix of at most {MAX_PREFIX} characters "
                    "plus a salted sha256) instead of the value itself")
            _reject_values(item, f"{path}.{key}")
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            _reject_values(item, f"{path}[{index}]")


def validate(raw: Any) -> Dict[str, Any]:
    """Check one measurement and return it normalised. Raises `MeasurementError`."""
    if not isinstance(raw, dict):
        raise MeasurementError("data_impact must be an object")
    # Value rejection runs first so someone who pastes a secret gets told what to do
    # instead of a generic "unknown key".
    _reject_values(raw)
    known = {"reachable", "enumeration", "sampled", "classes", "subjects",
             "fingerprints", "note"}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise MeasurementError(f"data_impact has unknown keys: {', '.join(unknown)}")

    reachable = raw.get("reachable")
    sampled = raw.get("sampled")
    for name, number in (("reachable", reachable), ("sampled", sampled)):
        if type(number) is not int or not 1 <= number <= MAX_REACHABLE:
            raise MeasurementError(f"data_impact.{name} must be an integer in "
                                   f"1..{MAX_REACHABLE}; how many items are there?")
    if sampled > reachable:
        raise MeasurementError("data_impact.sampled cannot exceed data_impact.reachable")

    enumeration = raw.get("enumeration")
    if enumeration not in ENUMERATIONS:
        raise MeasurementError(f"data_impact.enumeration must be one of "
                               f"{', '.join(ENUMERATIONS)}")

    classes = raw.get("classes")
    if not isinstance(classes, dict) or not classes:
        raise MeasurementError("data_impact.classes must say what the data is: "
                               f"a count per class from {', '.join(sorted(CLASSES))}")
    unknown_classes = sorted(set(map(str, classes)) - set(CLASSES))
    if unknown_classes:
        raise MeasurementError(f"unknown data classes: {', '.join(unknown_classes)}")
    if any(type(count) is not int or count < 1 for count in classes.values()):
        raise MeasurementError("each data_impact.classes count must be a positive integer")
    if sum(classes.values()) != sampled:
        raise MeasurementError(
            f"data_impact.classes counts total {sum(classes.values())} but sampled is "
            f"{sampled}; every item you characterised must be classified, and a claim "
            "about items you did not look at is not a measurement")

    top = tier_of(classes)
    subjects = raw.get("subjects", [])
    if (not isinstance(subjects, list) or len(subjects) > MAX_SUBJECTS or
            any(not isinstance(s, str) or not s.strip() or len(s) > MAX_SUBJECT_LEN
                for s in subjects)):
        raise MeasurementError(f"data_impact.subjects must be at most {MAX_SUBJECTS} "
                               "short descriptions of what the data is about")
    if top in ("sensitive", "credential") and not subjects:
        raise MeasurementError(
            f"a {top}-tier measurement needs data_impact.subjects: say what the data is "
            "about, because that is what the report has to explain")

    fingerprints = _fingerprints(raw.get("fingerprints", []))
    if top == "credential" and not fingerprints:
        raise MeasurementError(
            "a credential-tier measurement needs at least one data_impact.fingerprints "
            "entry (field name, redacted prefix, salted sha256) to bind the claim "
            "without storing the secret")

    note = " ".join(str(raw.get("note", "")).split())[:500]
    return {"reachable": reachable, "sampled": sampled, "enumeration": enumeration,
            "classes": {str(k): int(v) for k, v in sorted(classes.items())},
            "subjects": [" ".join(s.split()) for s in subjects],
            "fingerprints": fingerprints, "note": note,
            "tier": top, "ceiling": ceiling({"classes": classes, "reachable": reachable}),
            "reachable_is_lower_bound": enumeration == "bounded-sample"}


def _fingerprints(raw: Any) -> List[Dict[str, str]]:
    if not isinstance(raw, list) or len(raw) > MAX_FINGERPRINTS:
        raise MeasurementError(f"data_impact.fingerprints must be a list of at most "
                               f"{MAX_FINGERPRINTS} redacted entries")
    out = []
    for item in raw:
        if not isinstance(item, dict) or set(item) - {"field", "prefix", "sha256"}:
            raise MeasurementError("each fingerprint takes field, prefix and sha256 only")
        field, prefix, digest = item.get("field"), item.get("prefix", ""), item.get("sha256")
        if not isinstance(field, str) or not _FIELD.fullmatch(field):
            raise MeasurementError("each fingerprint needs the field or key name it came from")
        if not isinstance(prefix, str) or len(prefix) > MAX_PREFIX:
            raise MeasurementError(
                f"a fingerprint prefix is at most {MAX_PREFIX} characters; anything "
                "longer is the secret, not a fingerprint")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise MeasurementError("each fingerprint needs a salted sha256 (64 hex "
                                   "characters) of the value, never the value")
        out.append({"field": field, "prefix": prefix, "sha256": digest})
    return out


def ceiling(measurement: Any) -> str:
    """The highest severity this much of this kind of data can justify.

    An absent or uncharacterised measurement returns `UNMEASURED_CEILING`: the primitive
    may well be real, but nothing here evidences an impact beyond it.
    """
    if not isinstance(measurement, dict) or not measurement.get("classes"):
        return UNMEASURED_CEILING
    classes = measurement["classes"]
    reachable = measurement.get("reachable")
    if type(reachable) is not int or reachable < 1:
        return UNMEASURED_CEILING
    top = tier_of(classes)
    if top == "credential":
        return "critical"
    if top == "sensitive":
        if reachable >= SENSITIVE_CRITICAL:
            return "critical"
        return "high" if reachable >= SENSITIVE_HIGH else "medium"
    if top == "internal":
        return "medium"
    return "low"


def summarise(measurement: Dict[str, Any]) -> str:
    """One line for a report: how much, of what, and how sure the count is."""
    if not isinstance(measurement, dict) or not measurement.get("classes"):
        return "data not characterised; primitive proven, impact unmeasured"
    count = measurement["reachable"]
    qualifier = "at least " if measurement.get("reachable_is_lower_bound") else ""
    parts = ", ".join(f"{number} {name}" for name, number in
                      sorted(measurement["classes"].items(), key=lambda kv: -kv[1]))
    subjects = "; ".join(measurement.get("subjects") or [])
    tail = f" — {subjects}" if subjects else ""
    return (f"{qualifier}{count} items reachable, {measurement['sampled']} characterised "
            f"({parts}); {measurement['tier']}-tier{tail}")
