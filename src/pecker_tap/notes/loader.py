"""Notes loader: Markdown files under a notes checkout, frontmatter and line-numbered sections.

The checkout is read-only: this module opens files for reading and runs ``git rev-parse`` for the
commit SHA, nothing else. A note that cannot be read or parsed becomes a ``NoteParseError`` and the
other notes load as usual.

Line numbers are 1-based and count every line of the file, frontmatter included, so a claim's
``lines`` point at the line David sees in his editor. Line endings are normalised to ``\\n`` and a
leading byte order mark is dropped before anything else happens.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path, PurePosixPath
from typing import cast

import yaml
from pydantic import BaseModel, ConfigDict, Field

LIST_KEYS = ("sources", "cve", "ghsa", "extends", "supersedes")
SCALAR_KEYS = ("id", "decision", "review")
DECISION_AWAITING = "awaiting-david"

_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_HEADING = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$")
_CLOSING_HASHES = re.compile(r"[ \t]+#+$")
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Frontmatter(_Strict):
    id: str | None = None
    sources: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    ghsa: tuple[str, ...] = ()
    extends: tuple[str, ...] = ()
    supersedes: tuple[str, ...] = ()
    decision: str | None = None
    review: str | None = None
    unknown_keys: tuple[str, ...] = ()
    """Names of keys the verifier doesn't use (tolerated, never interpreted)."""


class Section(_Strict):
    index: int
    heading: str | None
    """``None`` for the text before the first heading."""
    level: int
    """Heading level 1 to 6; 0 for the text before the first heading."""
    first_line: int
    last_line: int


class Note(_Strict):
    path: str
    """POSIX path relative to the notes root."""
    text: str
    frontmatter: Frontmatter = Field(default_factory=Frontmatter)
    frontmatter_lines: tuple[int, int] | None = None
    sections: tuple[Section, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def lines(self) -> list[str]:
        return self.text.split("\n")

    @property
    def awaiting_decision(self) -> bool:
        return (self.frontmatter.decision or "").strip().lower() == DECISION_AWAITING

    def line_span(self, first: int, last: int) -> str:
        """The text of lines ``first`` to ``last`` (1-based, inclusive), joined with ``\\n``."""
        lines = self.lines
        if not 1 <= first <= last <= len(lines):
            return ""
        return "\n".join(lines[first - 1 : last])


class NoteParseError(_Strict):
    path: str
    message: str


class LoadResult(_Strict):
    notes: tuple[Note, ...] = ()
    errors: tuple[NoteParseError, ...] = ()


class FrontmatterError(ValueError):
    pass


def normalise_text(raw: str) -> str:
    text = raw.removeprefix("﻿")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _scalar(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dt.date | dt.datetime):
        return value.isoformat()
    if isinstance(value, str | int | float):
        return str(value).strip()
    return None


def _string_list(key: str, value: object, warnings: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    items: list[object] = (
        cast("list[object]", value) if isinstance(value, list | tuple) else [value]
    )
    result: list[str] = []
    for item in items:
        if isinstance(item, dict):
            url = cast("dict[object, object]", item).get("url")
            text = _scalar(url)
        else:
            text = _scalar(item)
        if text:
            result.append(text)
        else:
            warnings.append(f"frontmatter key {key!r}: an entry is not a plain value, skipped")
    return tuple(result)


def parse_frontmatter(block: str, warnings: list[str], first_line: int = 2) -> Frontmatter:
    """Parse the YAML between the ``---`` lines. Unknown keys are tolerated and only named.

    ``first_line`` is the file line of the block's first line, for error messages.
    """
    try:
        data: object = yaml.safe_load(block) if block.strip() else {}
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + first_line})" if mark is not None else ""
        msg = f"frontmatter is not valid YAML{where}"
        raise FrontmatterError(msg) from None
    if data is None:
        data = {}
    if not isinstance(data, dict):
        msg = "frontmatter is not a mapping of keys to values"
        raise FrontmatterError(msg)
    mapping = cast("dict[object, object]", data)
    values: dict[str, object] = {}
    unknown: list[str] = []
    for raw_key, value in mapping.items():
        key = str(raw_key)
        if key in LIST_KEYS:
            values[key] = _string_list(key, value, warnings)
        elif key in SCALAR_KEYS:
            text = _scalar(value)
            if value is not None and text is None:
                warnings.append(f"frontmatter key {key!r} is not a plain value, ignored")
            values[key] = text
        else:
            unknown.append(key)
    return Frontmatter.model_validate({**values, "unknown_keys": tuple(sorted(unknown))})


def split_sections(lines: Sequence[str], start: int) -> tuple[Section, ...]:
    """Split ``lines`` (the whole file) into sections from 1-based line ``start`` on.

    ATX headings (``#`` to ``######``) start a section unless they sit inside a fenced code block.
    Text before the first heading becomes a section without a heading if it isn't blank.
    """
    headings: list[tuple[int, int, str]] = []
    fence: str | None = None
    for number in range(start, len(lines) + 1):
        line = lines[number - 1]
        fence_match = _FENCE.match(line)
        if fence_match:
            marker = fence_match.group(1)
            stripped = line.strip()
            if fence is None:
                fence = marker
            elif set(stripped) == {fence[0]} and len(stripped) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        heading = _HEADING.match(line)
        if heading:
            title = _CLOSING_HASHES.sub("", heading.group(2) or "").strip()
            if title == "#" * len(title):
                title = ""
            headings.append((number, len(heading.group(1)), title))
    sections: list[Section] = []
    last = len(lines)
    while last >= start and not lines[last - 1].strip():
        last -= 1
    first_heading = headings[0][0] if headings else last + 1
    if any(lines[n - 1].strip() for n in range(start, min(first_heading, last + 1))):
        sections.append(
            Section(index=0, heading=None, level=0, first_line=start, last_line=first_heading - 1)
        )
    for position, (number, level, title) in enumerate(headings):
        end = headings[position + 1][0] - 1 if position + 1 < len(headings) else max(last, number)
        sections.append(
            Section(
                index=len(sections), heading=title, level=level, first_line=number, last_line=end
            )
        )
    return tuple(sections)


def parse_note(path: str, raw: str) -> Note:
    """Parse one note's text. Raises ``FrontmatterError`` for a broken frontmatter block."""
    text = normalise_text(raw)
    lines = text.split("\n")
    warnings: list[str] = []
    frontmatter = Frontmatter()
    fm_lines: tuple[int, int] | None = None
    body_start = 1
    if lines and lines[0].rstrip() == "---":
        closing = next(
            (n for n in range(2, len(lines) + 1) if lines[n - 1].rstrip() in {"---", "..."}),
            None,
        )
        if closing is None:
            msg = "frontmatter starts with --- but is never closed"
            raise FrontmatterError(msg)
        frontmatter = parse_frontmatter("\n".join(lines[1 : closing - 1]), warnings)
        fm_lines = (1, closing)
        body_start = closing + 1
    return Note(
        path=path,
        text=text,
        frontmatter=frontmatter,
        frontmatter_lines=fm_lines,
        sections=split_sections(lines, body_start),
        warnings=tuple(warnings),
    )


def _is_hidden(rel: PurePosixPath) -> bool:
    return any(part.startswith(".") for part in rel.parts)


def iter_note_files(root: Path, patterns: Sequence[str] = ()) -> Iterator[tuple[str, Path]]:
    """``(relative posix path, file)`` for every ``*.md`` under ``root``, sorted by path.

    Hidden folders and files are skipped, symbolic links to folders are not followed, and a linked
    file that points outside ``root`` is skipped. ``patterns`` are globs relative to ``root``
    (``**`` matches any number of folders); without patterns every note is selected.
    """
    resolved_root = root.resolve()
    found: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if not name.startswith("."))
        for name in filenames:
            if not name.endswith(".md") or name.startswith("."):
                continue
            path = Path(dirpath) / name
            rel = PurePosixPath(path.relative_to(root).as_posix())
            if _is_hidden(rel):
                continue
            if path.is_symlink() and not path.resolve().is_relative_to(resolved_root):
                continue
            if patterns and not any(rel.full_match(pattern) for pattern in patterns):
                continue
            found.append((rel.as_posix(), path))
    yield from sorted(found)


def load_notes(root: Path, patterns: Sequence[str] = ()) -> LoadResult:
    notes: list[Note] = []
    errors: list[NoteParseError] = []
    for rel, path in iter_note_files(root, patterns):
        try:
            raw = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            errors.append(NoteParseError(path=rel, message=f"not UTF-8 (byte {exc.start})"))
            continue
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            errors.append(NoteParseError(path=rel, message=f"cannot read: {reason}"))
            continue
        try:
            notes.append(parse_note(rel, raw))
        except FrontmatterError as exc:
            errors.append(NoteParseError(path=rel, message=str(exc)))
    return LoadResult(notes=tuple(notes), errors=tuple(errors))


def notes_sha(root: Path) -> str:
    """The checkout's commit SHA via ``git rev-parse`` (read-only), or ``unknown``."""
    git = shutil.which("git")
    if git is None:
        return "unknown"
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
    try:
        done = subprocess.run(  # noqa: S603 - fixed git subcommand, no shell
            [git, "-C", str(root), "-c", "core.fsmonitor=false", "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            timeout=10,
            check=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    sha = done.stdout.decode("ascii", errors="replace").strip()
    return sha if done.returncode == 0 and _SHA.fullmatch(sha) else "unknown"
