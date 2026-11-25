"""Version and range comparison per ecosystem (V1 brief, deliverable 7).

pip versions use PEP 440 (``packaging``); npm, crates.io, Go and similar ecosystems use semantic
versions (``semver``, a leading ``v`` and missing minor or patch parts allowed). Anything else, or
a version a parser refuses, is compared as a plain string and the comparison says so in a warning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import semver
from packaging.version import InvalidVersion, Version

PEP440_ECOSYSTEMS = frozenset({"pip", "pypi"})
SEMVER_ECOSYSTEMS = frozenset({"npm", "rust", "crates.io", "go", "golang", "nuget", "composer"})

_COMPARATOR = re.compile(r"(<=|>=|==|=|<|>)?\s*v?([0-9A-Za-z][0-9A-Za-z.+_-]*)")
_SPLIT = re.compile(r"\s*(?:,|\s)\s*")


@dataclass(frozen=True, slots=True)
class Normalised:
    key: str
    exact: bool
    """False when the version had to be compared as a string."""


def _scheme(ecosystem: str | None) -> str:
    eco = (ecosystem or "").lower()
    if eco in PEP440_ECOSYSTEMS:
        return "pep440"
    if eco in SEMVER_ECOSYSTEMS:
        return "semver"
    return "string"


def normalise_version(text: str, ecosystem: str | None) -> Normalised:
    raw = text.strip()
    scheme = _scheme(ecosystem)
    if scheme == "pep440":
        try:
            return Normalised(_pep440(raw), True)
        except InvalidVersion:
            pass
    elif scheme == "semver":
        try:
            parsed = semver.Version.parse(raw.removeprefix("v"), optional_minor_and_patch=True)
            return Normalised(str(parsed), True)
        except (ValueError, TypeError):
            pass
    return Normalised(raw.removeprefix("v").lower(), False)


def _pep440(raw: str) -> str:
    """PEP 440 normal form with trailing ``.0`` release parts removed (3.8 == 3.8.0)."""
    version = Version(raw)
    release = list(version.release)
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    parts = [f"{version.epoch}!" if version.epoch else "", ".".join(str(p) for p in release)]
    if version.pre:
        parts.append(f"{version.pre[0]}{version.pre[1]}")
    if version.post is not None:
        parts.append(f".post{version.post}")
    if version.dev is not None:
        parts.append(f".dev{version.dev}")
    if version.local:
        parts.append(f"+{version.local}")
    return "".join(parts)


def same_version(a: str, b: str, ecosystem: str | None) -> tuple[bool, bool]:
    """``(equal, exact)``: whether two versions are the same, and whether a parser decided it."""
    left, right = normalise_version(a, ecosystem), normalise_version(b, ecosystem)
    return left.key == right.key, left.exact and right.exact


def normalise_range(text: str, ecosystem: str | None) -> tuple[frozenset[str], bool]:
    """A range as a set of ``op version`` constraints; ``exact`` is False if any part wasn't parsed.

    ``>= 2.0.0, < 3.8.0``, ``>=2.0.0 <3.8.0`` and ``< 3.8.0, >= 2.0`` give the same set. A bare
    version means ``=``.
    """
    constraints: set[str] = set()
    exact = True
    for part in _SPLIT.split(text.strip()):
        if not part:
            continue
        match = _COMPARATOR.fullmatch(part)
        if match is None:
            constraints.add(part.lower())
            exact = False
            continue
        op = match.group(1) or "="
        op = "=" if op == "==" else op
        version = normalise_version(match.group(2), ecosystem)
        exact = exact and version.exact
        constraints.add(f"{op} {version.key}")
    return frozenset(constraints), exact


def _join_ops(text: str) -> str:
    """Glue a lone operator to its version (``< 3.8.0`` becomes ``<3.8.0``) before splitting."""
    return re.sub(r"(<=|>=|==|=|<|>)\s+", r"\1", text)


def same_range(a: str, b: str, ecosystem: str | None) -> tuple[bool, bool]:
    left, left_exact = normalise_range(_join_ops(a), ecosystem)
    right, right_exact = normalise_range(_join_ops(b), ecosystem)
    return left == right, left_exact and right_exact
