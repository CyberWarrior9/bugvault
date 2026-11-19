"""Conservative, offline JS call-site reconstruction (no code execution)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .jslex import Token, tokenize

_CLIENT = re.compile(r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*axios\.create\s*\(\s*\{[^}]{0,800}?\bbaseURL\s*:\s*['\"]([^'\"]+)['\"]")
_CONSTANT = re.compile(r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*['\"]([^'\"]{0,200})['\"]")
_HEADERS = re.compile(r"\.headers(?:\s*\[\s*['\"]([A-Za-z0-9-]{1,60})['\"]\s*\]|\.([A-Za-z][\w-]{0,60}))\s*=")
_BASEURL = re.compile(r"\bbaseURL\s*:\s*['\"]([^'\"]+)['\"]")
_KEY = re.compile(r"(?:^|[,{]\s*)['\"]?([A-Za-z_$][\w$]{0,40})['\"]?\s*:")
_INTERPOLATION = re.compile(r"\$\{([^{}]{1,120})\}")
_CALL_METHOD = {"get", "post", "put", "patch", "delete", "head"}


@dataclass
class Operation:
    raw: str
    method: Optional[str]
    params: List[str] = field(default_factory=list)
    transport: str = "unknown"
    headers: List[str] = field(default_factory=list)
    base: str = ""
    base_unresolved: bool = False
    signed: bool = False
    start: int = -1
    end: int = -1


def _args(tokens: List[Token], opener: int) -> List[List[Token]]:
    """Top-level args within one call, bounded to 2k tokens."""
    out: List[List[Token]] = [[]]
    stack = [")"]
    pairs = {"(": ")", "{": "}", "[": "]"}
    for t in tokens[opener + 1:opener + 2001]:
        if t.value in pairs:
            stack.append(pairs[t.value])
        elif t.value == stack[-1]:
            stack.pop()
            if not stack:
                break
        if t.value == "," and len(stack) == 1:
            out.append([])
        else:
            out[-1].append(t)
    return out


def _fold(tokens: List[Token], constants: Dict[str, str]) -> Tuple[str, bool]:
    """Literal + variable/templated parts; unknowns are placeholders, not values."""
    if not tokens:
        return "", False
    pieces = []
    unresolved = False
    for t in tokens:
        if t.kind == "string":
            pieces.append(t.value[1:-1].replace("\\/", "/"))
        elif t.kind == "template":
            body = t.value[1:-1]

            def repl(m):
                nonlocal unresolved
                expr = m.group(1).strip()
                if expr in constants:
                    return constants[expr]
                if m.start() == 0 and body[m.end():].startswith("/"):
                    unresolved = True
                    return ""
                return "{id}"

            pieces.append(_INTERPOLATION.sub(repl, body))
        elif t.value == "+":
            continue
        elif t.kind == "identifier" and t.value in constants:
            pieces.append(constants[t.value])
        elif t.kind in ("identifier", "number"):
            pieces.append("{id}")
        elif t.value == ".":
            continue
        else:
            return "", unresolved
    path = "".join(pieces)
    # Don't turn an unknown leading identifier into a new apparent root.
    if path.startswith("{id}/"):
        unresolved, path = True, path[4:]
    return path[:400], unresolved


def _instance_info(text: str) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    bases = dict(_CLIENT.findall(text))
    globals_: Dict[str, List[str]] = {}
    for client in bases:
        name = re.escape(client)
        for m in re.finditer(r"\b" + name + r"\.interceptors\.request\.use\s*\(", text):
            body = text[m.end():m.end() + 1200].split("});", 1)[0]
            globals_.setdefault(client, []).extend(a or b for a, b in _HEADERS.findall(body))
        for m in re.finditer(r"\b" + name + r"\.defaults\.baseURL\s*=\s*['\"]([^'\"]+)['\"]", text):
            bases[client] = m.group(1)
    return bases, {k: sorted(set(v))[:20] for k, v in globals_.items()}


def _transport(text: str, method: Optional[str]) -> str:
    if re.search(r"encryptPayload|encryptBody|encryptRequest|CryptoJS|signPayload", text):
        return "encrypted"
    if re.search(r"(?:Content-Type|content-type)['\"]?\s*:\s*['\"]application/x-www-form-urlencoded", text, re.I):
        return "form"
    if re.search(r"FormData\b|multipart/form-data", text, re.I):
        return "multipart"
    if re.search(r"qs\.stringify|URLSearchParams|x-www-form-urlencoded", text):
        return "form"
    if re.search(r"(?:Content-Type|content-type)['\"]?\s*:\s*['\"]application/json", text, re.I):
        return "json"
    if re.search(r"gql`|graphql`|\bquery\s*:\s*['\"]", text):
        return "graphql"
    if "JSON.stringify" in text or re.search(r"\b(?:body|data)\s*:\s*\{", text):
        return "json"
    if method == "GET":
        return "query"
    return "unknown"


def operations(text: str) -> List[Operation]:
    try:
        tokens = [t for t in tokenize(text) if t.kind != "comment"]
    except ValueError:
        return []
    constants = dict(_CONSTANT.findall(text))
    from .extract import SECRET_PATTERNS
    constants = {name: value for name, value in constants.items()
                 if not any(pattern.search(value) for pattern in SECRET_PATTERNS.values())}
    bases, globals_ = _instance_info(text)
    out: List[Operation] = []
    for i, t in enumerate(tokens):
        if t.kind != "identifier":
            continue
        if i and tokens[i - 1].value == ".":
            continue  # already handled as an instance method at the preceding token
        client = ""
        verb = t.value.lower()
        opener = i + 1
        if i + 3 < len(tokens) and tokens[i + 1].value == "." and tokens[i + 2].kind == "identifier":
            client, verb, opener = t.value, tokens[i + 2].value.lower(), i + 3
        if opener >= len(tokens) or tokens[opener].value != "(":
            continue
        if verb not in _CALL_METHOD and verb not in ("fetch", "sendbeacon"):
            continue
        if client and verb == "fetch":
            continue
        args = _args(tokens, opener)
        if not args or not args[0]:
            continue
        first = args[0]
        raw, unresolved = _fold(first, constants)
        if len(first) == 1 and first[0].kind == "template" and first[0].value.startswith("`/"):
            raw = first[0].value[1:-1]  # preserve the existing literal identity
        if not raw.startswith(("/", "http://", "https://", "ws://", "wss://")):
            continue
        base = bases.get(client, "")
        if base and raw.startswith("/"):
            raw = base.rstrip("/") + raw
        method: Optional[str] = verb.upper() if verb in _CALL_METHOD else None
        tail = text[first[-1].end:args[-1][-1].end] if args[-1] else ""
        if verb == "fetch":
            kv = re.search(r"\bmethod\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE|HEAD)['\"]", tail, re.I)
            method = kv.group(1).upper() if kv else None
        if verb == "sendbeacon":
            method = "POST"
        params = []
        for m in _KEY.finditer(tail):
            key = m.group(1)
            if key.lower() not in ("method", "body", "data", "params", "headers", "content-type",
                                   "url", "timeout", "signal", "credentials") and key not in params:
                params.append(key)
        op = Operation(raw, method, params[:30], _transport(tail, method),
                       globals_.get(client, []), base, unresolved,
                       bool(re.search(r"signPayload|signBody|nonce|timestamp", tail)),
                       first[0].start, first[-1].end)
        out.append(op)
    # Common path concatenation outside call sites (static lead, method unknown).
    for m in re.finditer(r"\b(?:const|let|var)\s+[\w$]+\s*=\s*(['\"]/[^;\n]{2,300});", text):
        try:
            expr = [t for t in tokenize(m.group(1)) if t.kind != "comment"]
        except ValueError:
            continue
        if any(t.value == "+" for t in expr):
            raw, unresolved = _fold(expr, constants)
            if raw.startswith("/"):
                out.append(Operation(raw, None, base_unresolved=unresolved,
                                     start=m.start(1), end=m.end(1)))
    return out[:3000]
