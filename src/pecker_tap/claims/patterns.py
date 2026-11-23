"""Identifier patterns and their canonical spelling.

GHSA IDs accept the digits 0 and 1 next to GitHub's own alphabet, so the synthetic fixture IDs
(``GHSA-0000-0000-0001``, AGENTS.md) parse; real GHSA IDs never use those digits.
"""

from __future__ import annotations

import re
from typing import Literal

IdKind = Literal["cve", "ghsa", "atlas", "owasp", "cwe"]

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
GHSA = re.compile(r"GHSA(?:-[0-9cfghjmpqrvwx]{4}){3}", re.IGNORECASE)
ATLAS = re.compile(r"AML\.(?:T\d{4}(?:\.\d{3})?|TA\d{4}|M\d{4}|CS\d{4})", re.IGNORECASE)
OWASP = re.compile(r"[A-Z]{1,4}\d{1,2}:\d{4}", re.IGNORECASE)
CWE = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)

PATTERNS: dict[IdKind, re.Pattern[str]] = {
    "cve": CVE,
    "ghsa": GHSA,
    "atlas": ATLAS,
    "owasp": OWASP,
    "cwe": CWE,
}

_BOUNDED: dict[IdKind, re.Pattern[str]] = {
    kind: re.compile(rf"(?<![\w-])(?:{pattern.pattern})(?![\w])", re.IGNORECASE)
    for kind, pattern in PATTERNS.items()
}

GITHUB_ADVISORY_URL = re.compile(
    r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})"
    r"/security/advisories/(GHSA(?:-[0-9cfghjmpqrvwx]{4}){3})",
    re.IGNORECASE,
)


def canonical(kind: IdKind, value: str) -> str:
    """The canonical spelling: CVE, CWE, AML and OWASP upper case; GHSA as ``GHSA-`` + lower."""
    text = value.strip()
    if kind == "ghsa":
        return "GHSA" + text[4:].lower()
    return text.upper()


def matches(kind: IdKind, value: str) -> bool:
    return PATTERNS[kind].fullmatch(value.strip()) is not None


def advisory_kind(value: str) -> Literal["cve", "ghsa"] | None:
    if matches("cve", value):
        return "cve"
    if matches("ghsa", value):
        return "ghsa"
    return None


def find_ids(kind: IdKind, text: str) -> list[str]:
    """Every ID of ``kind`` in ``text``, canonical, in order of first appearance, no repeats."""
    seen: dict[str, None] = {}
    for match in _BOUNDED[kind].finditer(text):
        seen.setdefault(canonical(kind, match.group(0)), None)
    return list(seen)
