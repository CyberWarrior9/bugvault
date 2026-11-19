"""Conservative, bounded asset edges from HTML import maps and service workers.

This module parses references only. It never evaluates JavaScript or sends a request;
callers must apply the campaign scope and request budget to every edge.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Tuple
from urllib.parse import urlsplit

from .extract import resolve

MAX_MAP = 200_000
MAX_EDGES = 500
_WORKER = re.compile(r"\b(?:navigator\.)?serviceWorker\.register\s*\(\s*['\"]([^'\"\s]{1,300})['\"]")
_IMPORT = re.compile(r"\bimport\s*(?:\(\s*|(?:[^;\n]{0,150}?\bfrom\s*))['\"]([^'\"\s]{1,200})['\"]")
_PRECACHE = re.compile(r"\b(?:self\.)?(?:__WB_MANIFEST|precacheAndRoute)\b")
_PRE_LITERAL = re.compile(r"(?:self\.)?(?:__WB_MANIFEST\s*=\s*|precacheAndRoute\s*\(\s*)\[")
_PRE_URL = re.compile(r"(?:\burl\s*:\s*|['\"]url['\"]\s*:\s*)['\"]([^'\"\s]{1,300})['\"]")
_QUOTED = re.compile(r"['\"]([^'\"\s]{1,300}\.(?:m?js|cjs|map)(?:\?[^'\"\s]*)?)['\"]")


def script_reference(url: str) -> bool:
    try:
        p = urlsplit(url)
        return (p.scheme in ("http", "https") and bool(p.hostname)
                and p.username is None and p.password is None
                and p.path.lower().endswith((".js", ".mjs", ".cjs", ".map")))
    except ValueError:
        return False


def worker_urls(text: str, base: str) -> List[str]:
    out = []
    for ref in _WORKER.findall(text[:MAX_MAP])[:MAX_EDGES]:
        try:
            out.append(resolve(base, ref))
        except ValueError:
            continue
    return list(dict.fromkeys(out))


def precache_urls(text: str, worker_url: str) -> Tuple[List[str], bool]:
    """Recognize Workbox-style *literal* arrays; dynamic expressions remain a gap."""
    original_len = len(text)
    text = text[:MAX_MAP]
    marker = _PRECACHE.search(text)
    if not marker:
        return [], False
    # Constrain to the literal array immediately after the marker; unrelated URL
    # constants later in the worker must not become precache edges.
    literal = _PRE_LITERAL.match(text, marker.start())
    if not literal:
        return [], True  # dynamic precache expression, not a proven complete list
    start = literal.end() - 1
    depth, quote, escape, end = 0, "", False, -1
    for i in range(start, min(len(text), start + 60_000)):
        c = text[i]
        if quote:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == quote:
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end < 0:
        return [], True
    window = text[start:end]
    refs = _PRE_URL.findall(window)
    refs.extend(_QUOTED.findall(window))
    urls = []
    malformed = False
    for ref in refs[:MAX_EDGES]:
        try:
            urls.append(resolve(worker_url, ref))
        except ValueError:
            malformed = True
    return list(dict.fromkeys(u for u in urls if script_reference(u))), (len(refs) > MAX_EDGES or
                                                                  original_len > MAX_MAP or malformed)


def importmap_urls(source: str, base: str, scripts: List[str]) -> Tuple[List[str], List[str]]:
    """Resolve literal manifest entries/imports; scopes/dynamic maps stay gaps."""
    if len(source) > MAX_MAP:
        return [], ["import map exceeds parser cap"]
    try:
        doc = json.loads(source)
    except (TypeError, ValueError):
        return [], ["import map is not JSON"]
    if not isinstance(doc, dict) or not isinstance(doc.get("imports", {}), dict):
        return [], ["import map imports is not an object"]
    mapping: Dict[str, str] = doc.get("imports", {})
    gaps = ["scoped import-map mappings require page-specific resolution"] if doc.get("scopes") else []
    # An import map is itself an asset manifest. Entries not referenced in the
    # current inline code are still candidates (external modules may use them).
    names = set(mapping) | {name for script in scripts for name in _IMPORT.findall(script[:MAX_MAP])}
    if len(names) > MAX_EDGES:
        gaps.append("import-map entry cap reached")
    urls = []
    for name in sorted(names)[:MAX_EDGES]:
        ref = mapping.get(name)
        if isinstance(ref, str):
            try:
                u = resolve(base, ref)
            except ValueError:
                gaps.append("unparseable import-map URL")
                continue
            if script_reference(u):
                urls.append(u)
        elif not name.startswith((".", "/", "http:" , "https:")):
            gaps.append("unresolved bare specifier: " + name[:80])
    return list(dict.fromkeys(urls)), gaps[:100]
