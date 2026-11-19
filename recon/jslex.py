"""Bounded, non-executing JavaScript lexer for call sites and real comments.

This is deliberately not a JS parser. Unknown syntax is retained as punctuation;
callers must keep uncertain matches as static leads, never as verified endpoints.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

MAX_TOKENS = 400_000


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int


def _quoted(text: str, i: int, quote: str) -> int:
    j = i + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
        elif text[j] == quote:
            return j + 1
        else:
            j += 1
    return len(text)


def _template(text: str, i: int) -> int:
    """Skip nested template expressions without mistaking their strings for comments."""
    j = i + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
        elif text[j] == "`":
            return j + 1
        elif text.startswith("${", j):
            j += 2
            level = 1
            while j < len(text) and level:
                if text[j] in "\"'":
                    j = _quoted(text, j, text[j])
                elif text[j] == "`":
                    j = _template(text, j)
                elif text.startswith("//", j):
                    end = text.find("\n", j + 2)
                    j = len(text) if end < 0 else end
                elif text.startswith("/*", j):
                    end = text.find("*/", j + 2)
                    j = len(text) if end < 0 else end + 2
                elif text[j] == "{":
                    level += 1
                    j += 1
                elif text[j] == "}":
                    level -= 1
                    j += 1
                else:
                    j += 1
        else:
            j += 1
    return len(text)


def tokenize(text: str) -> List[Token]:
    out: List[Token] = []
    i = 0
    prev = ""
    while i < len(text) and len(out) < MAX_TOKENS:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        start = i
        if c in "\"'":
            i = _quoted(text, i, c)
            kind = "string"
        elif c == "`":
            i = _template(text, i)
            kind = "template"
        elif text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = len(text) if end < 0 else end
            kind = "comment"
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            kind = "comment"
        elif c == "/" and prev in ("", "=", "(", "[", "{", ",", ":", "!", "return", "=>"):
            # A regex literal is not a // comment or a path string. Brackets and
            # escaped slashes are handled so `/https?:\/\/x/` stays one token.
            j, char_class = i + 1, False
            while j < len(text):
                if text[j] == "\\":
                    j += 2
                elif text[j] == "[":
                    char_class = True
                    j += 1
                elif text[j] == "]":
                    char_class = False
                    j += 1
                elif text[j] == "/" and not char_class:
                    j += 1
                    while j < len(text) and text[j].isalpha():
                        j += 1
                    break
                elif text[j] in "\r\n":
                    break
                else:
                    j += 1
            i, kind = j, "regex"
        elif c.isalpha() or c in "_$":
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] in "_$"):
                i += 1
            kind = "identifier"
        elif c.isdigit():
            i += 1
            while i < len(text) and (text[i].isalnum() or text[i] in "._"):
                i += 1
            kind = "number"
        else:
            i += 1
            kind = "punctuation"
        tok = Token(kind, text[start:i], start, i)
        out.append(tok)
        if kind != "comment":
            prev = tok.value if kind in ("punctuation", "identifier") else kind
    if i < len(text):
        raise ValueError("JS token budget exceeded; extraction incomplete")
    return out


def source_mapping_url(text: str) -> str:
    """Last annotation in a *real* line or block comment (not a JS string)."""
    import re
    refs = [m.group(1) for token in tokenize(text) if token.kind == "comment"
            for m in re.finditer(r"[#@]\s*sourceMappingURL=([^\s'\"*]+)", token.value)]
    return refs[-1] if refs else ""
