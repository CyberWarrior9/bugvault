"""Campaign config: scope + program policy. The single authority on what may be contacted.

Scope and policy are enforced in code (net.py calls Scope.check on every request and
every redirect hop, Policy.require on every job), never only in prompts.

scope.json lives in the campaign folder (vault/10-Campaigns/<name>/scope.json).
"""
from __future__ import annotations

import ipaddress
import json
import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlsplit

MODES = ("passive", "active", "loud")
ALLOWED_SCHEMES = ("http", "https", "ws", "wss")


class OutOfScope(Exception):
    pass


class PolicyViolation(Exception):
    pass


class ConfigError(Exception):
    pass


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


def norm_path(path: str) -> str:
    """Decode (up to 3 rounds), resolve dot segments, lowercase.

    Used for matching only, so `/a/../LOGOUT` and `/%6cogout` both match a `/logout` rule.
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
    return p.lower()


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

    def matches(self, scheme: str, host: str, path: str, port: Optional[int] = None) -> bool:
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
            if not (path == self.path or path.startswith(self.path + "/")):
                return False
        return True


def parse_rule(raw: str) -> Rule:
    s = (raw or "").strip()
    if not s:
        raise ConfigError("empty scope rule")
    if s.startswith("/"):
        p = norm_path(s)
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
    rule = Rule(raw=raw, scheme=scheme, path=norm_path(path) if path else None, port=port)
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
        path = norm_path(parts.path)
        for r in self.exclude:
            if r.matches(scheme, host, path, port):
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
        )
        if policy.mode not in MODES:
            raise ConfigError(f"policy.mode must be one of {MODES}, got {policy.mode!r}")
        if not (0 < policy.max_rps <= 50):
            raise ConfigError("policy.max_rps must be in (0, 50]")
        if not 1 <= policy.max_requests <= 100_000 or not 0 < policy.max_seconds <= 86_400:
            raise ConfigError("policy budgets: max_requests must be 1..100000; max_seconds in (0,86400]")
        if not 1 <= policy.max_body_bytes <= 50_000_000:
            raise ConfigError("policy.max_body_bytes must be 1..50000000")
        seeds = list(raw.get("seeds", []) or [])
        for s in seeds:
            target = s if "://" in s else f"https://{s}/"
            if not scope.is_in(target):
                raise ConfigError(f"seed {s!r} is not in scope")
        return cls(name=root.name, root=root, program=raw.get("program", root.name),
                   seeds=seeds, scope=scope, policy=policy,
                   runtime=dict(raw.get("runtime", {}) or {}), raw=raw)


def scope_template(program: str, seeds: List[str], mode: str) -> Dict[str, Any]:
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
        "policy": {
            "mode": mode,
            "_mode_help": "passive = never contact target (crt.sh, wayback only); "
                          "active = probe/harvest within program rules; "
                          "loud = brute-force-ish guesses (e.g. .map guessing). "
                          "Pick from the PROGRAM RULES, not from convenience.",
            "max_rps": 2,
            "max_requests": 1000,
            "max_seconds": 600,
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
    }
