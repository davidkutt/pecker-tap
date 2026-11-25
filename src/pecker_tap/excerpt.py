"""Escaped hostile text for packs and reports (adapted from pecker-drum).

Text from notes, model output and sources is data. Every excerpt is escaped and capped: invisible
and control characters are shown as ``\\uXXXX`` escapes, and the characters that could break out of
a Markdown code span or table cell (backtick, pipe, backslash) are escaped too, so nothing in a
summary renders as a live link, image or HTML. Evidence is capped at 300 characters (spec).
"""

from __future__ import annotations

import unicodedata

EXCERPT_LIMIT = 300
CLAIM_LIMIT = 500
_ELLIPSIS = "…"
_NAMED = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\\": "\\\\", "`": "\\x60", "|": "\\x7c"}


def _escape_char(char: str, *, inline: bool = True) -> str:
    if char in _NAMED and (inline or char not in "`|"):
        return _NAMED[char]
    category = unicodedata.category(char)
    if category in {"Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp"} or (category == "Zs" and char != " "):
        code = ord(char)
        return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"
    code = ord(char)
    if 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
        return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"
    return char


def escape_excerpt(text: str, limit: int = EXCERPT_LIMIT) -> str:
    """Escape ``text`` and cut it to ``limit`` characters (an escape is never split)."""
    pieces: list[str] = []
    length = 0
    for char in text:
        piece = _escape_char(char)
        if length + len(piece) > limit - 1:
            pieces.append(_ELLIPSIS)
            return "".join(pieces)
        pieces.append(piece)
        length += len(piece)
    return "".join(pieces)


def code_span(text: str) -> str:
    """Wrap an already escaped excerpt in a Markdown code span (renders as plain text)."""
    return f"`{text}`" if text else ""
