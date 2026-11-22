"""`recon exec`: external tools as a second *accounted* sending path.

Before this module, `AGENTS.md` said external tools "need manually enforced scope,
methods, pacing and shared budget accounting because recon does not enforce their
traffic". A manually enforced rule is not a rule. This module makes the enforcement
mechanical for an allowlisted set of tools, so `recon send` and `recon exec` are the
only two ways target traffic leaves this project, and both are charged to the same
campaign budget and the same per-host pacing clock (see `plans/artex-adoption.md` §3.1,
decision D1).

What is enforced in code, before the binary is launched:

* **Allowlist.** Six tool profiles. An unknown tool is refused, never passed through.
* **Scope.** Every target — behind a known flag, inside a `-list` file, or any argv
  token containing `://` — must pass `Scope.check`. One out-of-scope target refuses
  the whole run; nothing is launched.
* **Policy mode and methods.** A profile declares the HTTP methods its tool really
  sends. GET, HEAD and POST are always available (see `ALWAYS_AVAILABLE`); PUT, PATCH
  and DELETE still need an explicit `policy.allowed_methods` grant. Nothing runs in
  `passive` mode, whose whole promise is that the target is never contacted.
* **Pacing.** The tool's own rate flag is injected from `policy.max_rps` and cannot be
  overridden: a flag this module injects is refused in caller argv. The per-host
  `host_pacing` clock is also advanced across the whole run window, so a later
  `recon send` waits the scan out instead of stacking on top of it. That clock is the
  same best-effort mechanism `recon send` uses and its read-modify-write is **not
  atomic under simultaneous processes** (`recon/README.md`), so it is not a concurrent
  gate: run one sender at a time per campaign until the cross-process reservation of
  plan §4.4 lands with B3. The budget counter below *is* atomic.
* **Budget.** The declared `--estimate` is pre-charged to the shared campaign HTTP
  counter before the tool starts, and a wall-clock timeout derived from it bounds the
  run even for tools with no request-count flag.
* **Blocked hosts.** A host deferred by `recon engagement block-host` is refused.
* **Dangerous flags.** Per-tool refusals: payload-to-shell and file-write modes, WAF
  tamper ladders, third-party OOB callback servers, proxies, raw-request files,
  headless browsers outside the dedicated profile, and search-engine dorking.

**Reservations are never refunded.** No supported tool reports a trustworthy count of
the requests it made, so an unused estimate stays charged (decision D2: the budget may
only err towards stopping early). Reconciliation is upward only — if an artifact
contains more result records than the estimate, those records prove at least that many
requests were sent, and the difference is charged after the run.

A refusal here is a stop, not a detour: `AGENTS.md` forbids reaching for another tool
to get around a failed scope, rate or budget check.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .campaign import PolicyViolation
from .store import now

__all__ = ["PROFILES", "prepare", "execute", "Refused"]

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-z0-9]{8}$")
# A token that names a destination. Anything with a scheme separator is treated as a
# target and must pass the scope check, so `file:///etc/passwd` is refused rather than
# quietly handed to the tool.
SCHEMEY = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
#: Methods an allowlisted tool may use without a campaign `allowed_methods` grant.
#: POST is here because the scanners worth running (nuclei, dalfox, sqlmap) send POST
#: bodies as a matter of course; a grant check only ever blocked the run. Verb-level
#: mutation (PUT, PATCH, DELETE) is still gated.
ALWAYS_AVAILABLE = frozenset({"GET", "HEAD", "POST"})

MAX_LIST_LINES = 10_000
MAX_ARGV = 120
MAX_ARG_LEN = 4096
# Headers a caller may not set: the scoped client refuses the same ones, and an
# external tool must not be the loophole that gets them out.
BANNED_HEADER = re.compile(r"^\s*(host|proxy-authorization|proxy-connection)\s*:", re.I)


class Refused(PolicyViolation):
    """A run that will not be launched. Not a failure to route around.

    A refusal is a policy violation, not a bug: it subclasses `PolicyViolation` so it
    travels the same path as a scope or method failure everywhere else in recon.
    """


def _int(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise Refused(f"{name} must be an integer in {low}..{high}")
    return value


# ---------------------------------------------------------------------------
# Tool profiles
# ---------------------------------------------------------------------------

class Profile:
    """One allowlisted tool: how to find its targets and how to bound it.

    `sends` is the honest set of HTTP methods the tool uses, not the minimum it could
    be configured to use. nuclei, dalfox and sqlmap send POST bodies as a matter of
    course, so they require a POST grant; refusing is the safe outcome.
    """

    def __init__(self, tool: str, binary: str, mode: str, sends: Sequence[str], *,
                 target_flags: Sequence[str] = (), list_flags: Sequence[str] = (),
                 subcommand: bool = False, refuse: Sequence[str] = (),
                 ingest: str = "", artifact: str = "output.jsonl"):
        self.tool = tool
        self.binary = binary
        self.mode = mode
        self.sends = tuple(sends)
        self.target_flags = tuple(target_flags)
        self.list_flags = tuple(list_flags)
        self.subcommand = subcommand
        self.refuse = tuple(refuse)
        self.ingest = ingest
        self.artifact = artifact


PROFILES: Dict[str, Profile] = {
    "httpx": Profile(
        "httpx", "httpx", "active", ("GET", "HEAD"),
        target_flags=("-u", "-target"), list_flags=("-l", "-list"),
        # -ss/-screenshot drives a headless browser; browser work uses the dedicated
        # profile through Burp (AGENTS.md "Execution and evidence"), never this path.
        refuse=("-proxy", "-http-proxy", "-ss", "-screenshot", "-system-chrome"),
        ingest="httpx"),
    "katana": Profile(
        "katana", "katana", "active", ("GET",),
        target_flags=("-u",), list_flags=("-list", "-l"),
        refuse=("-proxy", "-headless", "-hl", "-system-chrome", "-cs", "-chrome-ws-url"),
        ingest="katana"),
    "ffuf": Profile(
        # Path and parameter guessing is the definition of `loud` in scope-policy:
        # "brute-force-ish guesses". It does not run on an `active` campaign.
        "ffuf", "ffuf", "loud", ("GET",),
        target_flags=("-u",),
        refuse=("-x", "-replay-proxy", "-request", "-request-proto", "-od", "-o", "-of"),
        ingest="ffuf", artifact="output.json"),
    "nuclei": Profile(
        "nuclei", "nuclei", "active", ("GET", "POST"),
        target_flags=("-u", "-target"), list_flags=("-l", "-list"),
        # -interactsh-server would route out-of-band callbacks through a third party
        # that no `callback_hosts` grant covers; -headless drives a browser; -ut
        # fetches templates over unaccounted egress; -code runs template code.
        refuse=("-proxy", "-p", "-interactsh-server", "-iserver", "-headless", "-system-chrome",
                "-ut", "-update", "-update-templates", "-code", "-sandbox"),
        ingest="nuclei"),
    "dalfox": Profile(
        "dalfox", "dalfox", "active", ("GET", "POST"),
        subcommand=True,
        # --found-action runs an arbitrary shell command on a hit. -b sends blind-XSS
        # callbacks to a host outside the approved receiver flow.
        refuse=("--proxy", "--found-action", "--found-action-shell", "-b", "--blind",
                "--har-file-path", "--remote-payloads", "--remote-wordlists"),
        ingest="", artifact="output.json"),
    "sqlmap": Profile(
        "sqlmap", "sqlmap", "active", ("GET", "POST"),
        target_flags=("-u", "--url"), list_flags=("-m",),
        # The shell/file-write family escalates past evidence into action; --tamper is a
        # WAF-evasion ladder, which AGENTS.md forbids; -g is search-engine dorking,
        # which picks its own targets; -r/-l take raw requests/logs whose real
        # destination this module cannot see to scope-check.
        refuse=("--proxy", "--tamper", "--os-shell", "--os-pwn", "--os-cmd", "--os-smbrelay",
                "--os-bof", "--priv-esc", "--file-write", "--file-dest", "--file-read",
                "--sql-shell", "--eval", "--crawl", "--purge", "--alert", "--beep",
                "-g", "-r", "-l", "-c", "--shell", "--answers", "--sqlmap-shell"),
        ingest=""),
}


def _injected(profile: Profile, rps: int, seconds: int, out: Path) -> List[str]:
    """Rate, concurrency, output and cap flags this module owns.

    A caller may not pass any of these: `_reserved` refuses them, so the campaign's
    pacing and the artifact location cannot be argued with from argv.
    """
    tool, name = profile.tool, str(out)
    delay_ms = max(1, int(round(1000.0 / rps)))
    if tool == "httpx":
        return ["-rate-limit", str(rps), "-timeout", "15", "-silent", "-json", "-o", name]
    if tool == "katana":
        return ["-rate-limit", str(rps), "-ct", str(seconds), "-silent", "-jsonl", "-o", name]
    if tool == "ffuf":
        return ["-rate", str(rps), "-maxtime", str(seconds), "-s", "-of", "json", "-o", name]
    if tool == "nuclei":
        return ["-rate-limit", str(rps), "-concurrency", "2", "-timeout", "10",
                "-no-interactsh", "-duc", "-silent", "-jsonl", "-o", name]
    if tool == "dalfox":
        return ["--delay", str(delay_ms), "--worker", "1", "--timeout", "15",
                "--no-spinner", "--format", "json", "-o", name]
    # sqlmap takes a float delay in seconds and has no total-request flag: the
    # wall-clock timeout is what actually bounds it.
    return ["--delay", f"{1.0 / rps:.3f}", "--threads", "1", "--batch",
            "--disable-coloring", f"--output-dir={out.parent}"]


def _reserved(profile: Profile, rps: int, seconds: int, out: Path) -> set:
    return {a.split("=", 1)[0] for a in _injected(profile, rps, seconds, out) if a.startswith("-")}


# ---------------------------------------------------------------------------
# argv inspection
# ---------------------------------------------------------------------------

def _pairs(argv: Sequence[str]) -> List[Tuple[str, Optional[str]]]:
    """Normalise argv into (flag-or-positional, value) pairs.

    `--flag=value` and `--flag value` are the same thing to a scope check, so both are
    flattened here rather than in each caller.
    """
    out: List[Tuple[str, Optional[str]]] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token.startswith("-") and "=" in token:
            flag, _, value = token.partition("=")
            out.append((flag, value))
        elif token.startswith("-") and index + 1 < len(argv) and not argv[index + 1].startswith("-"):
            out.append((token, argv[index + 1]))
            index += 1
        else:
            out.append((token, None))
        index += 1
    return out


def _hygiene(argv: Sequence[str]) -> None:
    if len(argv) > MAX_ARGV:
        raise Refused(f"tool argv is longer than {MAX_ARGV} arguments")
    for token in argv:
        if not isinstance(token, str) or len(token) > MAX_ARG_LEN:
            raise Refused(f"each tool argument must be a string of at most {MAX_ARG_LEN} characters")
        if any(ord(c) < 32 for c in token):
            raise Refused("tool arguments cannot contain control characters")
        if BANNED_HEADER.match(token):
            raise Refused("Host and proxy-authorization header overrides are refused, "
                          "as they are on the scoped client")


def _targets(profile: Profile, argv: Sequence[str], root: Path) -> List[str]:
    """Every destination this argv names, as URLs, from flags, lists and bare tokens."""
    found: List[str] = []
    pairs = _pairs(argv)

    if profile.subcommand:
        if not argv or argv[0] not in ("url", "file"):
            raise Refused("dalfox runs only as `url <target>` or `file <list>`; "
                          "pipe and server modes choose their own targets and are refused")
        if len(argv) < 2 or argv[1].startswith("-"):
            raise Refused(f"dalfox {argv[0]} needs a value")
        if argv[0] == "url":
            found.append(argv[1])
        else:
            found.extend(_from_list(argv[1], root))

    for flag, value in pairs:
        if flag in profile.target_flags:
            if not value:
                raise Refused(f"{flag} needs a target value")
            found.append(value)
        elif flag in profile.list_flags:
            if not value:
                raise Refused(f"{flag} needs a target-list file")
            found.extend(_from_list(value, root))

    # Fail closed on anything else that names a destination: a target behind a flag
    # alias this profile does not know is still a target.
    for token in argv:
        if SCHEMEY.match(token) and token not in found:
            found.append(token)
    if not found:
        raise Refused("no target found in argv; `recon exec` will not run a tool "
                      "whose destination it cannot see")
    return found


def _from_list(given: str, root: Path) -> List[str]:
    """Read a target-list file that must live inside the campaign directory."""
    path = Path(given)
    base = root.resolve()
    resolved = (base / path if not path.is_absolute() else path).resolve()
    if resolved.is_symlink() or not resolved.is_file():
        raise Refused(f"target list {given!r} must be an existing regular file")
    if base not in resolved.parents and resolved.parent != base:
        raise Refused("a target list must live inside the campaign directory")
    lines = [line.strip() for line in resolved.read_text(encoding="utf-8",
                                                         errors="strict").splitlines()]
    targets = [line for line in lines if line and not line.startswith("#")]
    if not targets:
        raise Refused(f"target list {given!r} is empty")
    if len(targets) > MAX_LIST_LINES:
        raise Refused(f"target list holds more than {MAX_LIST_LINES} targets")
    return targets


def _as_url(target: str) -> str:
    """A profile target may be a URL or a bare host; scope checks need a URL.

    ffuf marks the injection point with the literal `FUZZ`, which is not part of any
    host or path on the target. It is replaced before the check so the check sees a
    real URL, and the tool still receives the original argument.
    """
    cleaned = target.replace("FUZZ", "fuzz")
    if SCHEMEY.match(cleaned):
        return cleaned
    if "/" in cleaned:
        host, _, rest = cleaned.partition("/")
        return f"https://{host}/{rest}"
    return f"https://{cleaned}/"


# ---------------------------------------------------------------------------
# Preparation: everything that can refuse, before anything is launched
# ---------------------------------------------------------------------------

def prepare(ctx, tool: str, argv: Sequence[str], estimate: int, *,
            blocked: Optional[Dict[str, Any]] = None, resolve=shutil.which) -> Dict[str, Any]:
    """Validate a run and return the exact plan. Sends nothing; launches nothing."""
    if tool not in PROFILES:
        raise Refused(f"unknown tool {tool!r}; allowlisted: {', '.join(sorted(PROFILES))}")
    profile = PROFILES[tool]
    policy = ctx.campaign.policy
    estimate = _int(estimate, "--estimate", 1, policy.max_requests)
    argv = list(argv)
    _hygiene(argv)

    # Mode and methods: the same two gates `ScopedClient._send` applies.
    policy.require(profile.mode, f"{tool} external tool run")
    # GET, HEAD and POST are always available to an allowlisted tool (operator decision,
    # 2026-11-22): the scanners worth running send POST bodies as a matter of course, and
    # refusing them over a campaign's `allowed_methods` only stopped the run. Anything
    # that mutates state by verb — PUT, PATCH, DELETE — still needs its explicit grant.
    ungranted = [m for m in profile.sends
                 if m not in ALWAYS_AVAILABLE and m not in policy.allowed_methods]
    if ungranted:
        raise Refused(
            f"{tool} sends {', '.join(profile.sends)}; "
            f"policy.allowed_methods does not grant {', '.join(ungranted)}. "
            "Grant it in scope.json only if the program's written rules permit it.")
    if policy.proxy:
        raise Refused("a configured proxy cannot enforce pinned-peer egress; "
                      "external tool runs require direct transport")

    rps = max(1, int(policy.max_rps))
    seconds = max(1, math.ceil(estimate / rps))
    out_name = profile.artifact
    reserved = _reserved(profile, rps, seconds, Path(out_name))
    for flag, _ in _pairs(argv):
        if not flag.startswith("-"):
            continue
        if flag in profile.refuse:
            raise Refused(f"{tool} flag {flag} is refused by its profile in recon/toolexec.py")
        if flag in reserved:
            raise Refused(f"{flag} is set by recon from policy.max_rps and the campaign "
                          "layout; it cannot be overridden from argv")

    targets = _targets(profile, argv, ctx.campaign.root)
    hosts, checked = [], []
    for target in targets:
        url = _as_url(target)
        host = ctx.campaign.scope.check(url)  # raises OutOfScope
        checked.append({"given": target, "checked_as": url, "host": host})
        if host not in hosts:
            hosts.append(host)
    for host in hosts:
        if blocked and host in blocked:
            raise Refused(f"{host} is deferred by `recon engagement block-host` "
                          f"({blocked[host].get('reason')}); clear it first")

    binary = resolve(profile.binary)
    if not binary:
        raise Refused(
            f"{profile.binary} is not on PATH. This is an environment block: record it with "
            f"`recon operator ask --intent <id> --reason environment "
            f"--question 'install {profile.binary}, then paste the output of: "
            f"{profile.binary} -version'` and stop this attempt.")

    return {"tool": tool, "binary": binary, "caller_argv": argv, "targets": checked,
            "hosts": hosts, "estimate": estimate, "rps": rps, "seconds": seconds,
            "mode_required": profile.mode, "methods": list(profile.sends),
            "artifact_name": out_name, "ingest": profile.ingest,
            "timeout_seconds": seconds + 120, "executed": False}


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _run_dir(ctx, run_id: str) -> Path:
    state = ctx.campaign.state_dir
    if state.is_symlink():
        raise Refused("campaign state directory cannot be a symlink")
    path = state / "exec" / run_id
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    return path


def _env() -> Dict[str, str]:
    """A scrubbed environment: no inherited proxy can redirect the tool's traffic."""
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["NO_COLOR"] = "1"
    return env


def _digest(path: Path) -> Dict[str, Any]:
    data = path.read_bytes()
    return {"path": path.name, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def _records(path: Path, tool: str) -> int:
    """Result records in an artifact. Each one proves at least one request was sent."""
    if not path.is_file() or not path.stat().st_size:
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")
    if tool in ("ffuf", "dalfox"):
        try:
            data = json.loads(text)
        except ValueError:
            return 0
        rows = data.get("results") if isinstance(data, dict) else data
        return len(rows) if isinstance(rows, list) else 0
    return sum(1 for line in text.splitlines() if line.strip().startswith("{"))


def _atomic_json(path: Path, data: Dict[str, Any]) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".exec-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(data, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def execute(ctx, plan: Dict[str, Any], *, engagement: str = "",
            run_id: str = "", import_output: bool = True) -> Dict[str, Any]:
    """Charge the budget, pace the hosts, launch the tool, record what happened.

    The reservation happens before the launch and is never given back. If this process
    dies mid-run, the estimate stays charged: an unaccounted scan is the one outcome
    worth spending budget to avoid.
    """
    import secrets

    policy = ctx.campaign.policy
    run_id = run_id or f"{now().replace('-', '').replace(':', '')}-{secrets.token_hex(4)}"
    if not RUN_ID.fullmatch(run_id):
        raise Refused("run id must look like 20260101T000000Z-abcd1234")
    path = _run_dir(ctx, run_id)
    artifact = path / plan["artifact_name"]

    if not ctx.store.reserve_network_attempts(plan["estimate"], policy.max_campaign_requests):
        raise Refused(
            f"the campaign HTTP budget cannot cover {plan['estimate']} more attempts "
            f"({ctx.store.network_attempts()} of {policy.max_campaign_requests} used). "
            "A fresh campaign must not be used to evade exhaustion.")
    charged = plan["estimate"]

    # Hold the per-host pacing clock for the whole run window, so a `recon send` in
    # another process waits for the scan instead of adding its requests on top.
    for host in plan["hosts"]:
        ctx.store.reserve_pacing_slot(host, float(plan["seconds"]))

    argv = [plan["binary"], *plan["caller_argv"],
            *_injected(PROFILES[plan["tool"]], plan["rps"], plan["seconds"], artifact)]
    record: Dict[str, Any] = {
        "schema_version": 1, "run_id": run_id, "engagement": engagement,
        "tool": plan["tool"], "argv": argv[1:], "binary": plan["binary"],
        "targets": plan["targets"], "hosts": plan["hosts"],
        "estimate": plan["estimate"], "charged": charged,
        "rate_limit_rps": plan["rps"], "window_seconds": plan["seconds"],
        "methods": plan["methods"], "started": now(), "executed": True,
        "refund": "none; an unused estimate stays charged (decision D2)",
    }
    try:
        completed = subprocess.run(argv, cwd=str(path), env=_env(), shell=False,
                                   capture_output=True, timeout=plan["timeout_seconds"])
        record["exit_code"] = completed.returncode
        record["timed_out"] = False
        stdout, stderr = completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as expired:
        record["exit_code"] = None
        record["timed_out"] = True
        record["note"] = (f"killed at the {plan['timeout_seconds']}s cap derived from "
                          "--estimate and policy.max_rps")
        stdout, stderr = expired.stdout or b"", expired.stderr or b""
    except OSError as error:
        record["exit_code"] = None
        record["timed_out"] = False
        record["error"] = f"{type(error).__name__}: {error}"
        stdout, stderr = b"", b""

    for name, blob in (("stdout.txt", stdout), ("stderr.txt", stderr)):
        target = path / name
        target.write_bytes(blob[:5_000_000])
        os.chmod(target, 0o600)
    artifacts = [_digest(path / name) for name in ("stdout.txt", "stderr.txt")]
    if artifact.is_file():
        os.chmod(artifact, 0o600)
        artifacts.append(_digest(artifact))
    record["artifacts"] = artifacts
    record["result_records"] = _records(artifact, plan["tool"])

    # Upward-only reconciliation: N result records prove at least N requests.
    if record["result_records"] > charged:
        extra = record["result_records"] - charged
        if ctx.store.reserve_network_attempts(extra, policy.max_campaign_requests):
            record["charged"] = charged + extra
            record["reconciled"] = f"+{extra} from result records beyond the estimate"
        else:
            record["reconciled"] = (f"+{extra} owed from result records but the campaign "
                                    "budget is exhausted; stop and re-plan")
            record["budget_overrun"] = True

    record["ended"] = now()
    if import_output and plan["ingest"] and artifact.is_file() and artifact.stat().st_size:
        record["import"] = _import(ctx, artifact, plan["ingest"])
    _atomic_json(path / "run.json", record)
    _append(ctx, engagement, record)
    return record


def _import(ctx, artifact: Path, source: str) -> Dict[str, Any]:
    """Import surfaces through the existing offline importer, never as findings."""
    from .ingest import import_artifact
    try:
        return import_artifact(ctx, artifact, source)
    except (ValueError, TypeError, OSError) as error:
        return {"error": f"{type(error).__name__}: {error}",
                "note": "artifact kept; import it manually with `recon import`"}


def _append(ctx, engagement: str, record: Dict[str, Any]) -> None:
    """Append the run to the engagement's ledger under an exclusive lock."""
    if not engagement:
        return
    import fcntl
    if not NAME.fullmatch(engagement):
        raise Refused("engagement id must be a 1..64 character lowercase slug")
    folder = ctx.campaign.state_dir / "engagements" / engagement
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    ledger = folder / "exec-runs.jsonl"
    fd = os.open(folder / "exec-runs.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with open(ledger, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
        os.chmod(ledger, 0o600)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
