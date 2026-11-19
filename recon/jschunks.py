"""Bounded, offline chunk-URL reconstruction from *recognized* JS runtime shapes.

Never evaluates bundle code, guesses unreferenced manifests or widens target scope.
Incomplete/unknown runtime shapes must remain collection gaps rather than a claim
that every lazy chunk was enumerated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit

from .extract import resolve

MAX_RUNTIME = 6000
MAX_CHUNKS = 500
_TABLE = re.compile(
    r"\{((?:\s*(?:[0-9]+|['\"][0-9]+['\"]):\s*['\"][A-Za-z0-9_.\-/]{1,100}['\"]\s*,?){1,500})\}"
    r"\s*\[\s*(?:[\w$]+)\s*\]")
_ENTRY = re.compile(r"(?:^|,)\s*['\"]?([0-9]+)['\"]?\s*:\s*['\"]([A-Za-z0-9_.\-/]{1,100})['\"]")
_QUOTED_JS = re.compile(r"['\"]((?:(?:\.{0,2}/)?(?:static/)?(?:js|assets|chunks)/)[\w./@-]{0,160})['\"]\s*\+")
_SUFFIX = re.compile(r"['\"](\.chunk\.js|\.m?js)['\"]")
_REMOTE = re.compile(r"(?:[\w$.-]+@)?(https?://[^\s'\"`<>?]+/remoteEntry\.js)(?:\?[^\s'\"`<>]*)?")
_VITE = re.compile(r"\b__vite__mapDeps\b")
_VITE_DEPS = re.compile(r"(?:['\"])((?:\.?\.?/)?(?:assets/|static/)?[\w./@-]+\.m?js)(?:['\"])")
_MANIFEST = re.compile(r"\b__BUILD_MANIFEST\b")
_MANIFEST_ROUTE = re.compile(r"['\"](/[^'\"]*)['\"]\s*:\s*\[")
_PUBLIC_PATH = re.compile(r"\b[\w$]+\.p\s*=\s*['\"](/[^'\"?#]{0,120}/?)['\"]")


@dataclass(frozen=True)
class Chunk:
    url: str
    path: str
    source: str
    chunk_id: str = ""
    name: str = ""
    digest: str = ""


@dataclass
class ChunkGraph:
    chunks: List[Chunk] = field(default_factory=list)
    routes: List[str] = field(default_factory=list)
    remotes: List[str] = field(default_factory=list)
    composed_only: List[str] = field(default_factory=list)
    runtime_seen: bool = False
    gaps: List[str] = field(default_factory=list)


def manifest_routes(text: str) -> List[str]:
    """Only page keys inside a Next pages-router manifest are frontend routes."""
    m = _MANIFEST.search(text)
    if not m:
        return []
    section = text[m.end():m.end() + MAX_RUNTIME]
    return list(dict.fromkeys(r for r in _MANIFEST_ROUTE.findall(section)
                              if r not in ("/_app", "/_error", "/_document")))[:300]


def chunk_url(ref: str, script_url: str, public_path: str = "") -> str:
    """Resolve a bundler-rooted reference without inventing a new origin."""
    p = urlsplit(script_url)
    origin = urlunsplit((p.scheme, p.netloc, "", "", ""))
    if ref.startswith(("http://", "https://", "//")):
        return resolve(script_url, ref)
    if ref.startswith("/"):
        return origin + ref
    if public_path:
        return resolve(origin + public_path.rstrip("/") + "/", ref)
    if "/_next/static/" in p.path and ref.startswith(("static/", "_next/")):
        return origin + "/_next/" + ref.removeprefix("_next/")
    for part in ("static/", "assets/", "js/", "_nuxt/"):
        i = p.path.find("/" + part)
        if i >= 0 and ref.startswith(part):
            return origin + p.path[:i + 1] + ref
    if ref.startswith(("static/", "assets/", "js/", "_next/", "_nuxt/")):
        return origin + "/" + ref
    return resolve(script_url, ref)


def reconstruct(text: str, script_url: str, string_refs: Optional[List[str]] = None) -> ChunkGraph:
    graph = ChunkGraph()
    graph.routes = manifest_routes(text)
    # An out-of-scope federation remote is listed but never fetched here. The
    # caller's normal scope check is the sole authority for any later collection.
    graph.remotes = list(dict.fromkeys(_REMOTE.findall(text)))[:100]
    seen = set()

    def add(path: str, source: str, chunk_id: str = "", name: str = "", digest: str = "",
            public_path: str = "") -> None:
        if not path or path.startswith(".") and not path.startswith(("./", "../")):
            return
        url = chunk_url(path, script_url, public_path)
        if url not in seen and len(graph.chunks) < MAX_CHUNKS:
            graph.chunks.append(Chunk(url, path, source, chunk_id, name, digest))
            seen.add(url)

    # webpack 4's jsonpScriptSrc and webpack 5/rspack's .u(filename) are
    # identified by runtime shape, not a particular minifier's variable name.
    for marker in re.finditer(r"\bjsonpScriptSrc\b|\b[\w$]+\.u\s*=", text):
        graph.runtime_seen = True
        window = text[marker.start():marker.start() + MAX_RUNTIME]
        # Stop at the next statement/runtime assignment to prevent unrelated
        # maps elsewhere in a bundle from being combined with a filename template.
        window = window.split(";", 1)[0]
        prefix = _QUOTED_JS.search(window)
        suffixes = _SUFFIX.findall(window)
        tables = [dict(_ENTRY.findall(m.group(1))) for m in _TABLE.finditer(window)]
        hashes = next((t for t in tables if t and all(re.fullmatch(r"[A-Fa-f0-9]{6,64}", v)
                                                   for v in t.values())), {})
        names = next((t for t in tables if t and t is not hashes and
                      any(not re.fullmatch(r"[A-Fa-f0-9]{6,64}", v) for v in t.values())), {})
        if not prefix or not suffixes or not hashes:
            graph.gaps.append("unrecognized webpack filename template")
            continue
        before = text[max(0, marker.start() - 600):marker.start()]
        public = _PUBLIC_PATH.search(before)
        base = public.group(1) if public else ""
        for chunk_id, digest in list(hashes.items())[:MAX_CHUNKS]:
            name = names.get(chunk_id, chunk_id)
            path = prefix.group(1) + name + "." + digest + suffixes[-1]
            add(path, "webpack-runtime", chunk_id, name, digest, base)

    if _VITE.search(text):
        # Literal entries in the Vite dependency map; no evaluation of indexes.
        for m in re.finditer(r"\b__vite__mapDeps\b", text):
            snippet = text[m.end():m.end() + MAX_RUNTIME].split(";", 1)[0]
            for ref in _VITE_DEPS.findall(snippet)[:MAX_CHUNKS]:
                add(ref, "vite-dependency-map")

    if _MANIFEST.search(text):
        for ref in _VITE_DEPS.findall(text[_MANIFEST.search(text).end():][:MAX_RUNTIME]):
            if ref.startswith(("static/", "_next/")):
                add(ref, "next-manifest")

    # Plain string references are a baseline, not runtime-composed chunks. Their
    # URLs are compared to the graph but not counted as reconstruction output.
    from .extract import extract_from_js
    refs = string_refs if string_refs is not None else extract_from_js(text).chunks
    string_urls = {chunk_url(c, script_url) for c in refs}
    graph.composed_only = [c.url for c in graph.chunks if c.url not in string_urls]
    return graph
