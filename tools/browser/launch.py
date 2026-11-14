#!/usr/bin/env python3
"""Prepare or launch a separate visible Chrome profile using a loopback Burp proxy.

No personal Chrome profile, remote-debugging port, certificate bypass or system proxy
is used. Preparing the profile is not browser-control access or a campaign grant.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[2]
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
LABEL = "bugvault-agent-browser"


def proxy_address(url: str):
    parts = urlsplit(url)
    try:
        valid_host = ipaddress.ip_address(parts.hostname or "").is_loopback
        port = parts.port
    except ValueError as exc:
        raise ValueError("proxy must be an explicit loopback HTTP address and port") from exc
    if (parts.scheme != "http" or not valid_host or not port or parts.username is not None
            or parts.password is not None or parts.path not in ("", "/") or parts.query or parts.fragment):
        raise ValueError("proxy must be an explicit loopback HTTP address and port, without credentials")
    if port == 9876:
        raise ValueError("port 9876 is Burp MCP, not the browser web proxy (normally 8080)")
    return parts.hostname, port


def launch_plan(proxy="http://127.0.0.1:8080", repo=REPO, browser=CHROME):
    proxy_address(proxy)
    profile = Path(repo) / ".recon" / "browser" / "profile"
    command = [
        str(browser), f"--user-data-dir={profile}", "--profile-directory=Default",
        f"--proxy-server={proxy}", "--proxy-bypass-list=<-loopback>",
        "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-background-networking", "--disable-sync", "--no-first-run",
        "--no-default-browser-check", "--new-window", "about:blank",
    ]
    return {"label": LABEL, "profile": str(profile), "proxy": proxy, "command": command,
            "browser_control_connected": False,
            "note": "Visible persistent profile; extension connection and HTTPS CA trust still need setup. "
                    "Proxy flags cover browser web traffic, not OS-wide egress isolation."}


def prepare_profile(plan, repo=REPO):
    root = Path(repo)
    state, profile = root / ".recon" / "browser", Path(plan["profile"])
    if profile != state / "profile":
        raise ValueError("only BugVault's dedicated profile may be prepared")
    for path in (root / ".recon", state, profile):
        if path.is_symlink():
            raise ValueError("refusing a symlinked browser state/profile directory")
    marker = state / "owner.json"
    if marker.is_symlink():
        raise ValueError("refusing a symlinked browser ownership marker")
    if state.exists() and any(state.iterdir()):
        if not marker.is_file() or json.loads(marker.read_text()).get("label") != LABEL:
            raise ValueError("browser state is not marked as BugVault-owned; refusing to adopt it")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    profile.mkdir(exist_ok=True, mode=0o700)
    state.chmod(0o700)
    profile.chmod(0o700)
    marker.write_text(json.dumps({"label": LABEL}) + "\n")
    marker.chmod(0o600)
    manifest = state / "launch-plan.json"
    if manifest.is_symlink():
        raise ValueError("refusing a symlinked launch plan")
    manifest.write_text(json.dumps(plan, indent=2) + "\n")
    manifest.chmod(0o600)
    return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", default="http://127.0.0.1:8080",
                        help="loopback Burp HTTP proxy, NOT MCP port 9876")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="check binary/listener; do not create or launch")
    action.add_argument("--prepare", action="store_true", help="prepare private profile; do not launch Chrome")
    args = parser.parse_args(argv)
    try:
        plan = launch_plan(args.proxy)
        if not CHROME.is_file():
            raise ValueError(f"Chrome executable not found: {CHROME}")
        # A listening socket is a preflight, not proof of HTTP forwarding or TLS trust.
        with socket.create_connection(proxy_address(args.proxy), timeout=2):
            pass
        plan["proxy_listener_reachable"] = True
        if args.check:
            print(json.dumps(plan, indent=2))
            return 0
        state = prepare_profile(plan)
        if args.prepare:
            plan["status"] = "prepared, not launched"
        else:
            log = state / "chrome.log"
            if log.is_symlink():
                raise ValueError("refusing a symlinked browser log")
            with log.open("ab") as output:
                log.chmod(0o600)
                process = subprocess.Popen(plan["command"], stdin=subprocess.DEVNULL,
                                           stdout=output, stderr=subprocess.STDOUT,
                                           start_new_session=True)
            plan.update(status="launch requested; UI/control not verified", pid=process.pid)
        print(json.dumps(plan, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"Browser not launched: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
