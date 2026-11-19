"""Campaign config: scope + program policy. The single authority on what may be contacted.

Scope and policy are enforced in code (net.py calls Scope.check on every request and
every redirect hop, Policy.require on every job), never only in prompts.

scope.json lives in the campaign folder (vault/10-Campaigns/<name>/scope.json).
"""
from __future__ import annotations

import ipaddress
import json
import posixpath
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlsplit

MODES = ("passive", "active", "loud")
HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
ALLOWED_SCHEMES = ("http", "https", "ws", "wss")
AUTHZ_PROBES = frozenset({"method-matrix", "sibling-expand", "representation-fuzz",
                          "id-mutation", "read-extraction", "write-proof"})
AUTHZ_CHAINS = frozenset({"token-use", "lateral", "persistence"})
UPLOAD_GRANTS = frozenset({"contrast", "transport", "derivative", "callback", "cross-account"})
_RECEIVER_HOST = re.compile(r"(?:\*\.)?[a-zA-Z0-9][a-zA-Z0-9.-]*")
BL_FAMILY = re.compile(r"BL-(?:0[1-9]|1[0-8])")
RC_FAMILY = re.compile(r"RC-(?:0[1-9]|1[0-9]|2[01])")
BL_PERMITS = frozenset({"state-changing", "sensitive-read"})


class OutOfScope(Exception):
    pass


class PolicyViolation(Exception):
    pass


class ConfigError(Exception):
    pass


def validate_authz(raw: Any) -> Dict[str, Any]:
    """Fail-closed offline authorization-ledger grants, never network permissions."""
    if not isinstance(raw, dict) or any(k not in (
            "probe_grants", "chain_grants", "probe_budget", "_help")
            for k in raw):
        raise ConfigError("authz must be an object with known grant/budget keys")
    result: Dict[str, Any] = {}
    for key, known in (("probe_grants", AUTHZ_PROBES), ("chain_grants", AUTHZ_CHAINS)):
        values = raw.get(key, [])
        if (not isinstance(values, list) or len(values) != len(set(map(str, values)))
                or any(not isinstance(v, str) or v not in known for v in values)):
            raise ConfigError(f"authz.{key} must be a unique list from {sorted(known)}")
        result[key] = frozenset(values)
    budget = raw.get("probe_budget", {})
    if not isinstance(budget, dict) or set(budget) - {"requests", "per_host", "readonly_variants"}:
        raise ConfigError("authz.probe_budget contains unknown bounds")
    requests, per_host = budget.get("requests", 0), budget.get("per_host", 0)
    readonly = budget.get("readonly_variants", 8)
    if (type(requests) is not int or type(per_host) is not int or
            type(readonly) is not int or not 1 <= readonly <= 8 or
            not 0 <= per_host <= requests <= 1000 or
            (result["probe_grants"] or result["chain_grants"]) and per_host == 0):
        raise ConfigError("authz.probe_budget needs 0..1000 requests and 0..requests "
                          "per_host; grants require positive limits")
    result["probe_budget"] = {"requests": requests, "per_host": per_host,
                              "readonly_variants": readonly}
    return result


def validate_upload(raw: Any) -> Dict[str, Any]:
    """Fail-closed hunt-file-upload ledger labels copied from the program's published rules.

    These gate offline evidence recording only. They never widen scope, methods,
    the native request budget or Burp/scanner traffic.
    """
    if not isinstance(raw, dict) or any(k not in (
            "rules_reviewed", "case_grants", "budget", "callback_hosts", "retention_days", "_help")
            for k in raw):
        raise ConfigError("upload must be an object with known rule/grant/budget keys")
    reviewed = raw.get("rules_reviewed", "")
    if not isinstance(reviewed, str) or reviewed and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", reviewed):
        raise ConfigError("upload.rules_reviewed must be an ISO date (YYYY-MM-DD) or empty")
    if reviewed:
        try:
            date.fromisoformat(reviewed)
        except ValueError as exc:
            raise ConfigError("upload.rules_reviewed is not a calendar date") from exc
    grants = raw.get("case_grants", [])
    if (not isinstance(grants, list) or len(grants) != len(set(map(str, grants)))
            or any(not isinstance(g, str) or g not in UPLOAD_GRANTS for g in grants)):
        raise ConfigError(f"upload.case_grants must be a unique list from {sorted(UPLOAD_GRANTS)}")
    budget = raw.get("budget", {})
    if not isinstance(budget, dict) or set(budget) - {"requests", "per_host", "bytes", "objects"}:
        raise ConfigError("upload.budget contains unknown bounds")
    values = {key: budget.get(key, 0) for key in ("requests", "per_host", "bytes", "objects")}
    if (any(type(v) is not int for v in values.values()) or
            not 0 <= values["per_host"] <= values["requests"] <= 10_000 or
            not 0 <= values["bytes"] <= 50_000_000 or not 0 <= values["objects"] <= 1000 or
            grants and (values["per_host"] == 0 or values["objects"] == 0)):
        raise ConfigError("upload.budget needs 0..10000 requests, 0..requests per_host, "
                          "0..50000000 bytes and 0..1000 objects; case grants require positive "
                          "per_host and objects")
    hosts = raw.get("callback_hosts", [])
    if not isinstance(hosts, list) or len(hosts) > 20 or any(
            not isinstance(h, str) or not _RECEIVER_HOST.fullmatch(h) for h in hosts):
        raise ConfigError("upload.callback_hosts must list at most 20 exact or *.suffix receiver hosts")
    retention = raw.get("retention_days", 7)
    if type(retention) is not int or not 1 <= retention <= 90:
        raise ConfigError("upload.retention_days must be 1..90")
    return {"rules_reviewed": reviewed, "case_grants": frozenset(grants), "budget": values,
            "callback_hosts": list(hosts), "retention_days": retention}


def _reviewed(value: Any, name: str) -> str:
    if not isinstance(value, str) or value and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ConfigError(f"{name} must be an ISO date (YYYY-MM-DD) or empty")
    if value:
        try:
            date.fromisoformat(value)
        except ValueError as exc:
            raise ConfigError(f"{name} is not a calendar date") from exc
    return value


def _labels(values: Any, name: str, valid) -> frozenset:
    if (not isinstance(values, list) or len(values) != len(set(map(str, values))) or any(
            not isinstance(v, str) or not (valid.fullmatch(v) if hasattr(valid, "fullmatch")
                                           else v in valid) for v in values)):
        raise ConfigError(f"{name} must be a unique list of known labels")
    return frozenset(values)


def _bounds(raw: Any, name: str, spec: Dict[str, tuple]) -> Dict[str, int]:
    if not isinstance(raw, dict) or set(raw) - set(spec):
        raise ConfigError(f"{name} contains unknown bounds")
    out = {}
    for key, (low, high, default) in spec.items():
        value = raw.get(key, default)
        if type(value) is not int or not low <= value <= high:  # bool is not an integer cap
            raise ConfigError(f"{name}.{key} must be an integer in {low}..{high}")
        out[key] = value
    return out


def validate_business_logic(raw: Any) -> Dict[str, Any]:
    """Offline readiness labels for hunt-business-logic, copied from published program rules.

    Absent config permits offline review and owned-lab work only. Labels gate ledger
    readiness/recording; they never widen scope, methods or any traffic budget.
    """
    if not isinstance(raw, dict) or set(raw) - {"policy_reviewed", "families", "permits",
                                                 "budget", "retention_days", "owned_accounts", "_help"}:
        raise ConfigError("business_logic must be an object with known keys")
    reviewed = _reviewed(raw.get("policy_reviewed", ""), "business_logic.policy_reviewed")
    families = _labels(raw.get("families", []), "business_logic.families", BL_FAMILY)
    permits = _labels(raw.get("permits", []), "business_logic.permits", BL_PERMITS)
    owned = raw.get("owned_accounts", [])
    if (not isinstance(owned, list) or len(owned) > 10 or len(set(map(str, owned))) != len(owned) or
            any(not isinstance(v, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,79}", v)
                for v in owned)):
        raise ConfigError("business_logic.owned_accounts must list at most ten owned test account labels")
    budget = _bounds(raw.get("budget", {}), "business_logic.budget",
                     {"requests": (0, 10_000, 0), "per_host": (0, 10_000, 0),
                      "objects": (0, 1000, 0), "value_cap_minor": (0, 1_000_000_000, 0)})
    retention = raw.get("retention_days", 7)
    if type(retention) is not int or not 1 <= retention <= 90:
        raise ConfigError("business_logic.retention_days must be 1..90")
    if budget["per_host"] > budget["requests"]:
        raise ConfigError("business_logic.budget.per_host cannot exceed requests")
    if (families or permits or owned) and not reviewed:
        raise ConfigError("business_logic families/permits need policy_reviewed from the published rules")
    if families and budget["per_host"] == 0:
        raise ConfigError("business_logic families need a positive per_host budget")
    return {"policy_reviewed": reviewed, "families": families, "permits": permits,
            "owned_accounts": tuple(owned), "budget": budget, "retention_days": retention}


def validate_race(raw: Any) -> Dict[str, Any]:
    """Offline readiness labels for hunt-race-conditions; no grant creates a synchronized sender."""
    if not isinstance(raw, dict) or set(raw) - {"policy_reviewed", "families", "burst", "_help"}:
        raise ConfigError("race must be an object with known keys")
    reviewed = _reviewed(raw.get("policy_reviewed", ""), "race.policy_reviewed")
    families = _labels(raw.get("families", []), "race.families", RC_FAMILY)
    burst = _bounds(raw.get("burst", {}), "race.burst",
                    {"max_parallelism": (0, 30, 0), "max_runs": (1, 5, 5), "max_points": (1, 3, 3)})
    if (families or burst["max_parallelism"]) and not reviewed:
        raise ConfigError("race families/burst need policy_reviewed from the published rules")
    return {"policy_reviewed": reviewed, "families": families, "burst": burst}


def validate_cloud(raw: Any) -> Dict[str, Any]:
    """Cloud evidence labels; NOT grants for HTTP/SDK/Burp traffic.

    Exact actions, owned resources, scope, execution channel and budgets still
    come from the program rules and the private approved run plan.
    """
    if not isinstance(raw, dict) or set(raw) - {"rules_reviewed", "grants", "budget", "_help"}:
        raise ConfigError("cloud accepts rules_reviewed, grants and budget only")
    reviewed = _reviewed(raw.get("rules_reviewed", ""), "cloud.rules_reviewed")
    from .cloud import GRANTS
    grants = _labels(raw.get("grants", []), "cloud.grants", GRANTS)
    budget = raw.get("budget", 0)
    if type(budget) is not int or not 0 <= budget <= 100_000:
        raise ConfigError("cloud.budget must be 0..100000 declared requests")
    if grants and (not reviewed or budget == 0):
        raise ConfigError("cloud evidence grants require a rules review and positive budget")
    return {"rules_reviewed": reviewed, "grants": grants, "budget": budget}


def validate_js(raw: Any, policy: "Policy") -> Dict[str, Any]:
    """JS acquisition limits only. No config label is a scope/method grant."""
    keys = {"rules_reviewed", "max_js_per_origin", "max_bundle_bytes", "max_map_bytes",
             "archived_content", "stale", "probe", "secret_validation", "_help"}
    if not isinstance(raw, dict) or set(raw) - keys:
        raise ConfigError("js must be an object with known keys")
    reviewed = _reviewed(raw.get("rules_reviewed", ""), "js.rules_reviewed")
    cap = min(5_000_000, policy.max_body_bytes)
    limit = raw.get("max_js_per_origin", 300)
    bundle = raw.get("max_bundle_bytes", cap)
    source_map = raw.get("max_map_bytes", cap)
    if type(limit) is not int or not 1 <= limit <= 3000:
        raise ConfigError("js.max_js_per_origin must be 1..3000")
    if any(type(n) is not int or not 1 <= n <= policy.max_body_bytes
           for n in (bundle, source_map)):
        raise ConfigError("js byte limits must be positive and at most policy.max_body_bytes")
    archive = raw.get("archived_content", False)
    if type(archive) is not bool or archive and not reviewed:
        raise ConfigError("js.archived_content needs a reviewed-rules date")
    stale = raw.get("stale", {})
    if not isinstance(stale, dict) or set(stale) - {"max_builds", "max_old_assets"}:
        raise ConfigError("js.stale must have only max_builds/max_old_assets")
    builds, old = stale.get("max_builds", 5), stale.get("max_old_assets", 0)
    if type(builds) is not int or not 2 <= builds <= 20:
        raise ConfigError("js.stale.max_builds must be 2..20")
    if type(old) is not int or not 0 <= old <= 1000:
        raise ConfigError("js.stale.max_old_assets must be 0..1000")
    if old and not reviewed:
        raise ConfigError("js.stale.max_old_assets needs a reviewed-rules date")
    probe = raw.get("probe", {})
    if not isinstance(probe, dict) or set(probe) - {"enabled", "budget"}:
        raise ConfigError("js.probe must be an object with enabled/budget")
    enabled, budget = probe.get("enabled", False), probe.get("budget", 0)
    if type(enabled) is not bool or type(budget) is not int or not 0 <= budget <= policy.max_requests:
        raise ConfigError("js.probe budget must not exceed policy.max_requests")
    if enabled:
        raise ConfigError("jsprobe is not implemented; leave js.probe.enabled=false")
    validation = raw.get("secret_validation", "none")
    if validation not in ("none", "identity-only"):
        raise ConfigError("js.secret_validation must be none or identity-only")
    if validation != "none" and not reviewed:
        raise ConfigError("js.secret_validation needs a reviewed-rules date")
    return {"max_js_per_origin": limit, "max_bundle_bytes": bundle,
            "max_map_bytes": source_map, "archived_content": archive,
            "stale": {"max_builds": builds, "max_old_assets": old},
            "probe": {"enabled": False, "budget": budget},
            "secret_validation": validation, "rules_reviewed": reviewed}


def norm_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host and not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return host


def norm_path(path: str, casefold: bool = True) -> str:
    """Decode (up to 3 rounds), resolve dot segments, optionally lowercase.

    Exclusions are conservatively case-insensitive; includes preserve path case.
    """
    p = path or "/"
    for _ in range(3):
        decoded = unquote(p)
        if decoded == p:
            break
        p = decoded
    p = p.replace("\\", "/")
    p = posixpath.normpath("/" + p.lstrip("/"))
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    return p.lower() if casefold else p


def _split_hostport(hostpart: str) -> str:
    hostpart = hostpart.rsplit("@", 1)[-1]
    if hostpart.startswith("["):
        return hostpart[1:hostpart.find("]")] if "]" in hostpart else hostpart
    if hostpart.count(":") == 1:
        return hostpart.split(":", 1)[0]
    return hostpart


@dataclass
class Rule:
    raw: str
    scheme: Optional[str] = None
    host: Optional[str] = None
    suffix: Optional[str] = None
    net: Any = None
    path: Optional[str] = None
    port: Optional[int] = None

    def matches(self, scheme: str, host: str, path: str, port: Optional[int] = None,
                ignore_path_case: bool = False) -> bool:
        if self.scheme and scheme != self.scheme:
            return False
        if self.port is not None and port != self.port:
            return False
        if self.net is not None:
            try:
                if ipaddress.ip_address(host) not in self.net:
                    return False
            except ValueError:
                return False
        elif self.suffix:
            if not host.endswith("." + self.suffix):
                return False
        elif self.host:
            if host != self.host:
                return False
        if self.path and self.path != "/":
            allowed_path = self.path.lower() if ignore_path_case else self.path
            if not (path == allowed_path or path.startswith(allowed_path + "/")):
                return False
        return True


def parse_rule(raw: str) -> Rule:
    s = (raw or "").strip()
    if not s:
        raise ConfigError("empty scope rule")
    if s.startswith("/"):
        p = norm_path(s, casefold=False)
        if p == "/":
            raise ConfigError("path rule '/' would match everything")
        return Rule(raw=raw, path=p)
    scheme = None
    path = None
    if "://" in s:
        parts = urlsplit(s)
        scheme = parts.scheme.lower()
        hostpart = parts.netloc
        path = parts.path or None
    else:
        hostpart, _, rest = s.partition("/")
        if rest and rest.isdigit():
            try:
                return Rule(raw=raw, net=ipaddress.ip_network(s, strict=False))
            except ValueError as e:
                raise ConfigError(f"bad CIDR {s!r}: {e}")
        if rest:
            path = "/" + rest
    host = _split_hostport(hostpart)
    if host in ("*", "") or host.startswith("*") and not host.startswith("*."):
        raise ConfigError(f"scope rule too broad or malformed: {raw!r}")
    try:
        authority = hostpart
        if not scheme and authority.count(":") > 1 and not authority.startswith("["):
            try:
                ipaddress.IPv6Address(authority)
                authority = f"[{authority}]"
            except ValueError:
                pass
        parsed = urlsplit(s if scheme else "//" + authority)
        if parsed.username is not None or parsed.password is not None:
            raise ConfigError("scope rules cannot contain credentials")
        port = parsed.port
        if port == 0:
            raise ConfigError("scope port must be 1..65535")
        if scheme and scheme not in ALLOWED_SCHEMES:
            raise ConfigError("unsupported scope scheme")
        if scheme and port is None:
            port = 443 if scheme in ("https", "wss") else 80
    except ValueError as e:
        raise ConfigError(f"invalid scope port: {raw!r}") from e
    rule = Rule(raw=raw, scheme=scheme, path=norm_path(path, casefold=False) if path else None, port=port)
    if host.startswith("*."):
        rule.suffix = norm_host(host[2:])
    else:
        h = norm_host(host)
        try:
            rule.net = ipaddress.ip_network(h)
        except ValueError:
            rule.host = h
    return rule


@dataclass
class Scope:
    include: List[Rule]
    exclude: List[Rule]

    @classmethod
    def from_lists(cls, include: List[str], exclude: List[str]) -> "Scope":
        if not include:
            raise ConfigError("in_scope is empty")
        allowed = [parse_rule(r) for r in include]
        if any(not (r.host or r.suffix or r.net is not None) for r in allowed):
            raise ConfigError("in_scope rules must name a host/network; path-only rules are exclusions")
        return cls(allowed, [parse_rule(r) for r in exclude or []])

    def check(self, url: str) -> str:
        """Return the normalized host if `url` is in scope, else raise OutOfScope."""
        try:
            parts = urlsplit(url)
            scheme = parts.scheme.lower()
            host = norm_host(parts.hostname or "")
            port = parts.port or (443 if scheme in ("https", "wss") else 80)
            if parts.port == 0:
                raise OutOfScope("URL port must be 1..65535")
            if parts.username is not None or parts.password is not None:
                raise OutOfScope("URLs containing credentials are not allowed")
        except ValueError as e:
            raise OutOfScope(f"unparseable URL {url!r}: {e}")
        if scheme not in ALLOWED_SCHEMES:
            raise OutOfScope(f"scheme {scheme!r} not allowed: {url}")
        if not host:
            raise OutOfScope(f"no host in {url!r}")
        path = norm_path(parts.path, casefold=False)
        for r in self.exclude:
            if r.matches(scheme, host, path.lower(), port, ignore_path_case=True):
                raise OutOfScope(f"{url} matches out_of_scope rule {r.raw!r}")
        for r in self.include:
            if r.matches(scheme, host, path, port):
                return host
        raise OutOfScope(f"{url} matches no in_scope rule")

    def is_in(self, url: str) -> bool:
        try:
            self.check(url)
            return True
        except OutOfScope:
            return False

    def host_in(self, host: str) -> bool:
        h = norm_host(host)
        if ":" in h:  # IPv6
            h = f"[{h}]"
        return self.is_in(f"https://{h}/")

    def mentions_host(self, host: str) -> bool:
        """Conservatively recognize a target name regardless of allowed URL paths/ports."""
        h = norm_host(host)
        return any(r.matches(r.scheme or "https", h, r.path or "/", r.port) for r in self.include)


@dataclass
class Policy:
    mode: str = "passive"
    max_rps: float = 2.0
    user_agent: str = "bugvault-recon"
    headers: Dict[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    proxy: Optional[str] = None
    max_body_bytes: int = 5_000_000
    max_requests: int = 1000
    max_seconds: float = 600.0
    max_campaign_requests: int = 10_000
    allowed_ip_ranges: List[str] = field(default_factory=list)
    denied_ip_ranges: List[str] = field(default_factory=list)
    # Read-only by default. Write methods are an explicit operator grant for programs
    # whose rules permit active/state-changing testing.
    allowed_methods: List[str] = field(default_factory=lambda: ["GET", "HEAD"])

    def allows(self, need: str) -> bool:
        return MODES.index(self.mode) >= MODES.index(need)

    def require(self, need: str, what: str) -> None:
        if not self.allows(need):
            raise PolicyViolation(
                f"{what} needs mode {need!r}; campaign policy mode is {self.mode!r}")


@dataclass
class Campaign:
    name: str
    root: Path
    program: str
    seeds: List[str]
    scope: Scope
    policy: Policy
    runtime: Dict[str, Any]
    raw: Dict[str, Any]

    @property
    def state_dir(self) -> Path:
        return self.root / ".recon"

    @property
    def db_path(self) -> Path:
        return self.state_dir / "recon.db"

    @property
    def bodies_dir(self) -> Path:
        return self.state_dir / "bodies"

    @classmethod
    def load(cls, root: Path) -> "Campaign":
        root = Path(root)
        cfg_path = root / "scope.json"
        if not cfg_path.exists():
            raise ConfigError(f"{cfg_path} not found (run: python3 -m recon init ...)")
        try:
            raw = json.loads(cfg_path.read_text())
        except json.JSONDecodeError as e:
            raise ConfigError(f"{cfg_path}: {e}")
        scope = Scope.from_lists(raw.get("in_scope", []), raw.get("out_of_scope", []))
        validate_authz(raw.get("authz", {}))
        validate_upload(raw.get("upload", {}))
        validate_business_logic(raw.get("business_logic", {}))
        validate_race(raw.get("race", {}))
        validate_cloud(raw.get("cloud", {}))
        from .takeover import validate_config as validate_takeover
        try:
            validate_takeover(raw.get("takeover", {}))
        except (ValueError, TypeError) as exc:
            raise ConfigError(str(exc)) from exc
        pol = raw.get("policy", {}) or {}
        policy = Policy(
            mode=pol.get("mode", "passive"),
            max_rps=float(pol.get("max_rps", 2.0)),
            user_agent=pol.get("user_agent", "bugvault-recon"),
            headers=dict(pol.get("headers", {}) or {}),
            verify_tls=bool(pol.get("verify_tls", True)),
            proxy=pol.get("proxy"),
            max_body_bytes=int(pol.get("max_body_bytes", 5_000_000)),
            max_requests=int(pol.get("max_requests", 1000)),
            max_seconds=float(pol.get("max_seconds", 600)),
            max_campaign_requests=int(pol.get("max_campaign_requests", 10_000)),
            allowed_ip_ranges=list(pol.get("allowed_ip_ranges", []) or []),
            denied_ip_ranges=list(pol.get("denied_ip_ranges", []) or []),
            allowed_methods=[str(m).upper() for m in pol.get("allowed_methods", ["GET", "HEAD"])],
        )
        if policy.mode not in MODES:
            raise ConfigError(f"policy.mode must be one of {MODES}, got {policy.mode!r}")
        if not (0 < policy.max_rps <= 50):
            raise ConfigError("policy.max_rps must be in (0, 50]")
        if not 1 <= policy.max_requests <= 100_000 or not 0 < policy.max_seconds <= 86_400:
            raise ConfigError("policy budgets: max_requests must be 1..100000; max_seconds in (0,86400]")
        if not 1 <= policy.max_body_bytes <= 50_000_000:
            raise ConfigError("policy.max_body_bytes must be 1..50000000")
        if not 1 <= policy.max_campaign_requests <= 1_000_000:
            raise ConfigError("policy.max_campaign_requests must be 1..1000000")
        js_config = validate_js(raw.get("js", {}), policy)
        if js_config["stale"]["max_old_assets"] and not raw.get("program_url"):
            raise ConfigError("active retired-JS fetches need program_url and reviewed published rules")
        try:
            for network in policy.allowed_ip_ranges + policy.denied_ip_ranges:
                ipaddress.ip_network(network)
        except (TypeError, ValueError) as exc:
            raise ConfigError("IP egress ranges must be valid IPv4/IPv6 CIDRs") from exc
        if (not policy.allowed_methods or len(set(policy.allowed_methods)) != len(policy.allowed_methods)
                or any(m not in HTTP_METHODS for m in policy.allowed_methods)
                or "GET" not in policy.allowed_methods):
            raise ConfigError("policy.allowed_methods must be a unique non-empty subset of "
                              f"{sorted(HTTP_METHODS)} and include GET")
        if any(m not in ("GET", "HEAD") for m in policy.allowed_methods) and policy.mode == "passive":
            raise ConfigError("policy.allowed_methods write methods require mode active or loud")
        seeds = list(raw.get("seeds", []) or [])
        collection = raw.get("collection", {})
        if not isinstance(collection, dict):
            raise ConfigError("collection must be an object")
        for key, default, maximum in (("max_pages", 1, 100), ("max_depth", 2, 5)):
            value = collection.get(key, default)
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < (1 if key == "max_pages" else 0) or value > maximum):
                raise ConfigError(f"collection.{key} has an invalid bound")
        for s in seeds:
            target = s if "://" in s else f"https://{s}/"
            if not scope.is_in(target):
                raise ConfigError(f"seed {s!r} is not in scope")
        return cls(name=root.name, root=root, program=raw.get("program", root.name),
                   seeds=seeds, scope=scope, policy=policy,
                   runtime=dict(raw.get("runtime", {}) or {}), raw=raw)


def scope_template(program: str, seeds: List[str], mode: str,
                   allowed_methods: Optional[List[str]] = None) -> Dict[str, Any]:
    # Extra methods are an explicit init-time grant, not implied by active mode.
    methods = list(dict.fromkeys(["GET", "HEAD"] + [m.upper() for m in allowed_methods or []]))
    if mode not in MODES:
        raise ConfigError(f"policy.mode must be one of {MODES}, got {mode!r}")
    if any(m not in HTTP_METHODS for m in methods):
        raise ConfigError(f"policy.allowed_methods must use supported methods: {sorted(HTTP_METHODS)}")
    if mode == "passive" and any(m not in ("GET", "HEAD") for m in methods):
        raise ConfigError("policy.allowed_methods beyond GET/HEAD require mode active or loud")
    in_scope: List[str] = []
    for s in seeds:
        if "://" in s:
            in_scope.append(s)
        else:
            in_scope.append(s)  # a seed never authorizes all its subdomains
    return {
        "program": program,
        "platform": "hackerone",
        "program_url": "",
        "seeds": seeds,
        "in_scope": in_scope,
        "out_of_scope": ["/logout", "/signout"],
        "rules": [],
        "_rules_help": "Paste the program's testing rules, one per line; they are copied "
                       "verbatim into the agent briefs (python3 -m recon brief).",
        "excluded_bug_classes": [],
        "collection": {"max_pages": 1, "max_depth": 2},
        "policy": {
            "mode": mode,
            "_mode_help": "passive = never contact target (crt.sh, wayback only); "
                          "active = probe/harvest within program rules; "
                          "loud = brute-force-ish guesses (e.g. .map guessing). "
                          "Pick from the PROGRAM RULES, not from convenience.",
            "max_rps": 2,
            "max_requests": 1000,
            "max_seconds": 600,
            "max_campaign_requests": 10000,
            "allowed_ip_ranges": [],
            "denied_ip_ranges": [],
            "allowed_methods": methods,
            "_allowed_methods_help": "Read-only recon by default. Add POST/PUT/PATCH/DELETE/OPTIONS "
                                     "only when the program's written rules permit state-changing "
                                     "tests; every request is still scope-, rate- and budget-checked.",
            "user_agent": "bugvault-recon (authorized bug bounty; contact: YOUR_HANDLE)",
            "headers": {},
            "verify_tls": True,
            "proxy": None,
        },
        "runtime": {
            "enabled": False,
            "_help": "Headless SPA harvest: API calls are answered with mocks, never sent "
                     "to the backend (unless live_api=true, GET only).",
            "stubs": [],
            "local_storage": None,
            "cookies": [],
            "live_api": False,
            "max_routes": 60,
            "max_clicks_per_page": 15,
        },
        "js": {
            "rules_reviewed": "", "max_js_per_origin": 300,
            "max_bundle_bytes": 5_000_000, "max_map_bytes": 5_000_000,
            "archived_content": False,
            "stale": {"max_builds": 5, "max_old_assets": 0},
            "probe": {"enabled": False, "budget": 0},
            "secret_validation": "none",
            "_help": "JS parsing is offline after scoped collection. Archive body fetching "
                     "and probes are off until separately reviewed; this block never widens scope."
        },
        "ssrf": {
            "depth_grants": [],
            "_depth_grants_help": "Deep-branch techniques the program's written rules allow: "
                                  "dns, internal, cloud, credential, protocol, execution, or [\"all\"]. "
                                  "Grants unlock hunt-ssrf case branches and chain ranking; every "
                                  "destination still passes scope checks and live tests still use "
                                  "the dedicated browser through Burp.",
            "callback_hosts": [],
            "_callback_hosts_help": "Exact hosts or *.suffix patterns approved for controlled "
                                    "callback receivers (offline evidence matching only).",
        },
        "ssti": {
            "depth_grants": [],
            "_depth_grants_help": "Post-evaluation depth the program's written rules allow: "
                                  "context, file-read, execution, or [\"all\"]. Grants unlock "
                                  "hunt-ssti depth evidence recording only; live actions still "
                                  "run in the dedicated browser through Burp and every destination "
                                  "still passes scope checks.",
            "callback_hosts": [],
            "_callback_hosts_help": "Exact hosts or *.suffix patterns approved for controlled "
                                     "SSTI OOB receivers; falls back to ssrf.callback_hosts.",
        },
        "authz": {
            "probe_grants": [], "chain_grants": [],
            "probe_budget": {"requests": 0, "per_host": 0, "readonly_variants": 8},
            "_help": "Offline hunt-access-control grant labels only. Copy explicitly from "
                     "written program rules and a standing execution plan; no grant widens "
                     "scope, method permissions or native/external traffic budgets."
        },
        "takeover": {
            "rules_reviewed": "", "grants": [], "budget": 0, "providers": []
        },
        "upload": {
            "rules_reviewed": "", "case_grants": [],
            "budget": {"requests": 0, "per_host": 0, "bytes": 0, "objects": 0},
            "callback_hosts": [], "retention_days": 7,
            "_help": "hunt-file-upload ledger labels. Set program_url, then the date you reviewed "
                     "the program's published upload rules; grant only case families those rules "
                     "permit (contrast, transport, derivative, callback, cross-account). The budget "
                     "covers browser, Burp, native and scanner upload traffic together. Labels never "
                     "widen scope or method permissions."
        },
        "business_logic": {
            "policy_reviewed": "", "families": [], "permits": [],
            "budget": {"requests": 0, "per_host": 0, "objects": 0, "value_cap_minor": 0},
            "retention_days": 7,
            "_help": "hunt-business-logic / hunt-race-conditions shared ledger labels. Record the "
                     "date you reviewed the program's published rules, the BL-xx families they "
                     "permit live, and permits (state-changing, sensitive-read) only if allowed. "
                     "The budget is shared by both views. Absent labels mean offline/owned-lab only."
        },
        "race": {
            "policy_reviewed": "", "families": [],
            "burst": {"max_parallelism": 0, "max_runs": 5, "max_points": 3},
            "_help": "RC-xx families and operator-run burst allowance copied from published rules. "
                     "No synchronized sender exists in recon; concurrent live runs are operator-run "
                     "Burp groups only, recorded as declared external evidence."
        },
    }
