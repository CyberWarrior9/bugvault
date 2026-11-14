"""DNS-validated socket connections for built-in HTTP clients, not a shell sandbox.

Resolve once per connection, reject an unsafe/mixed answer set, and connect to a
validated numeric sockaddr without resolving again. HTTP Host and TLS SNI retain the
original hostname. No process-wide monkey-patching or system firewall changes.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import time
import urllib.request
from typing import Optional

from .campaign import PolicyViolation, norm_host


class EgressViolation(PolicyViolation):
    pass


def address_ip(value: str):
    address = ipaddress.ip_address(value)
    return address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address


class ConnectionGuard:
    def __init__(self, campaign, store, *, intel: bool = False):
        self.campaign, self.store, self.intel = campaign, store, intel
        self.allowed = [ipaddress.ip_network(n) for n in campaign.policy.allowed_ip_ranges]
        self.denied = [ipaddress.ip_network(n) for n in campaign.policy.denied_ip_ranges]

    def _allowed(self, ip, literal) -> bool:
        if ip.is_unspecified or ip.is_multicast or any(ip in n for n in self.denied):
            return False
        # CIDR/IP exclusions are also enforced on resolved peers (fail closed).
        if not self.intel:
            for rule in self.campaign.scope.exclude:
                if rule.net is not None and ip in rule.net:
                    return False
        if ip.is_global:
            return True
        if self.intel:
            return False  # public intel providers must not resolve to local networks
        # An explicitly scoped numeric private address is an explicit local/lab grant.
        return ip == literal or any(ip in n for n in self.allowed)

    def connect(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        host, port = address
        host = norm_host(host)
        try:
            literal = address_ip(host)
        except ValueError:
            literal = None
        peers = []
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            if not infos or len(infos) > 64:
                raise EgressViolation("DNS answer set empty or exceeds connection limit")
            for family, kind, protocol, _, sockaddr in infos:
                ip = address_ip(sockaddr[0])
                peers.append(str(ip))
                if not self._allowed(ip, literal):
                    raise EgressViolation(f"connection to {host}:{port} rejected by IP egress policy")
            # Deduplicate while preserving resolver ordering; never re-resolve during connect.
            unique = {(family, kind, protocol, sockaddr): None
                      for family, kind, protocol, _, sockaddr in infos}
            last_error = None
            deadline = time.monotonic() + timeout if isinstance(timeout, (int, float)) else None
            for family, kind, protocol, sockaddr in unique:
                sock = socket.socket(family, kind, protocol)
                try:
                    if deadline is not None:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise socket.timeout("connection deadline exhausted")
                        sock.settimeout(remaining)
                    if source_address:
                        sock.bind(source_address)
                    sock.connect(sockaddr)
                    peer = sock.getpeername()
                    if address_ip(peer[0]) != address_ip(sockaddr[0]) or peer[1] != sockaddr[1]:
                        raise EgressViolation("connected peer does not match pinned DNS address")
                    self.store.connection_event(host, port, peers, str(address_ip(sockaddr[0])), "connected")
                    return sock
                except Exception as exc:
                    sock.close()
                    if not isinstance(exc, OSError):
                        raise
                    last_error = exc
            raise last_error or OSError("no usable socket address")
        except (OSError, PolicyViolation) as exc:
            self.store.connection_event(host, port, peers, None,
                                        "blocked" if isinstance(exc, PolicyViolation) else "failed")
            raise


def _connection(cls, guard, host, **kwargs):
    conn = cls(host, **kwargs)
    # http.client deliberately exposes this connection factory for transport substitution.
    conn._create_connection = guard.connect
    return conn


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, guard):
        super().__init__()
        self.guard = guard

    def http_open(self, req):
        return self.do_open(lambda host, **kw: _connection(http.client.HTTPConnection,
                                                          self.guard, host, **kw), req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, guard, context):
        super().__init__(context=context)
        self.guard = guard

    def https_open(self, req):
        return self.do_open(lambda host, **kw: _connection(http.client.HTTPSConnection,
                                                          self.guard, host, **kw), req,
                            context=self._context, check_hostname=self._check_hostname)
