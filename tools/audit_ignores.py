"""Ignore list for the pip-audit job.

``tools/audit_ignores.toml`` lists the known vulnerabilities pip-audit may skip. Every entry needs
an ``id``, a non-empty ``reason`` and an ``expires`` date that is today or later and at most
``MAX_DAYS`` days ahead. An expired, incomplete or unknown entry fails the job.

``python tools/audit_ignores.py [FILE]`` prints one ``--ignore-vuln=<id>`` per entry, ready for the
pip-audit command line, or lists the problems and exits with 1.

Dev-only: not part of the ``pecker_tap`` package, standard library only.
"""

from __future__ import annotations

import re
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import cast

MAX_DAYS = 90
DEFAULT_FILE = Path(__file__).with_name("audit_ignores.toml")
_ID = re.compile(r"[A-Z]+-[A-Za-z0-9-]+")
_KEYS = frozenset({"id", "reason", "expires"})


class IgnoreListError(ValueError):
    """The ignore list breaks a rule; ``problems`` names each one."""

    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = tuple(problems)


@dataclass(frozen=True, slots=True)
class Ignore:
    id: str
    reason: str
    expires: date


def _entry(index: int, raw: object, today: date) -> tuple[Ignore | None, list[str]]:
    where = f"ignore[{index}]"
    if not isinstance(raw, dict):
        return None, [f"{where}: must be a table with id, reason and expires"]
    entry = cast("dict[str, object]", raw)
    problems: list[str] = []
    unknown = sorted(set(entry) - _KEYS)
    if unknown:
        problems.append(f"{where}: unknown keys {', '.join(unknown)}")
    vuln_id = entry.get("id")
    if not isinstance(vuln_id, str) or not _ID.fullmatch(vuln_id):
        problems.append(f"{where}: id must look like GHSA-..., PYSEC-... or CVE-...")
    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        problems.append(f"{where}: reason is missing")
    expires = entry.get("expires")
    if not isinstance(expires, date) or isinstance(expires, datetime):
        problems.append(f"{where}: expires must be a date (YYYY-MM-DD)")
    elif expires < today:
        problems.append(f"{where}: expired on {expires.isoformat()}, review it")
    elif expires > today + timedelta(days=MAX_DAYS):
        problems.append(f"{where}: expires more than {MAX_DAYS} days ahead ({expires.isoformat()})")
    if problems or not (
        isinstance(vuln_id, str) and isinstance(reason, str) and isinstance(expires, date)
    ):
        return None, problems
    return Ignore(vuln_id, reason.strip(), expires), []


def load(text: str, today: date) -> list[Ignore]:
    """Parse and check an ignore list; raises ``IgnoreListError`` with every problem."""
    try:
        data: dict[str, object] = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise IgnoreListError([f"not valid TOML: {exc}"]) from exc
    unknown = sorted(set(data) - {"ignore"})
    raw_entries = data.get("ignore", [])
    problems = [f"unknown top-level keys {', '.join(unknown)}"] if unknown else []
    if not isinstance(raw_entries, list):
        raise IgnoreListError([*problems, "ignore must be a list of tables"])
    entries: list[Ignore] = []
    for index, raw in enumerate(cast("list[object]", raw_entries)):
        entry, entry_problems = _entry(index, raw, today)
        problems += entry_problems
        if entry is not None:
            entries.append(entry)
    seen: set[str] = set()
    for entry in entries:
        if entry.id in seen:
            problems.append(f"{entry.id}: listed twice")
        seen.add(entry.id)
    if problems:
        raise IgnoreListError(problems)
    return entries


def pip_audit_args(entries: Sequence[Ignore]) -> list[str]:
    return [f"--ignore-vuln={entry.id}" for entry in entries]


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    path = Path(args[0]) if args else DEFAULT_FILE
    try:
        entries = load(path.read_text(encoding="utf-8"), datetime.now(UTC).date())
    except IgnoreListError as exc:
        print(f"{path}: the pip-audit ignore list breaks the rules:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    for entry in entries:
        print(f"{path}: ignoring {entry.id} until {entry.expires}: {entry.reason}", file=sys.stderr)
    print("\n".join(pip_audit_args(entries)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
