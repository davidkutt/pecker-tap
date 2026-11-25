"""Tracked docs carry no invisible format or control characters (AGENTS.md).

Fixtures may hold such characters on purpose (attack text); docs never do. Write them as
escapes instead, for example ``\\u200b``. Every file under ``docs/`` is scanned, so a file that is
not UTF-8 is reported too. The checker lives in ``tools/text_guard.py``; CI uses the same
script for commit messages and pull request text.
"""

from pathlib import Path

import pytest
from text_guard import doc_files, findings

ROOT = Path(__file__).resolve().parents[1]


def plant(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")
    return path


@pytest.mark.parametrize(
    "path", doc_files(ROOT), ids=lambda path: path.relative_to(ROOT).as_posix()
)
def test_tracked_doc_has_no_format_or_control_characters(path: Path) -> None:
    found = findings(path, ROOT)
    assert not found, "format or control characters, write them as escapes:\n" + "\n".join(found)


def test_scope_is_the_named_docs_only() -> None:
    scanned = {path.relative_to(ROOT).as_posix() for path in doc_files(ROOT)}
    assert {"README.md", "AGENTS.md", "fixtures/README.md", "docs/spec.md"} <= scanned
    assert "docs/milestones/V1.md" in scanned
    outside = {rel for rel in scanned if not rel.startswith("docs/")}
    assert outside <= {"README.md", "AGENTS.md", "SECURITY.md", "fixtures/README.md"}


def test_planted_zero_width_space_is_reported_with_file_line_and_code_point(
    tmp_path: Path,
) -> None:
    plant(tmp_path, "docs/notes.md", "# Notes\nsplit\u200bword\n")
    assert [f for p in doc_files(tmp_path) for f in findings(p, tmp_path)] == [
        "docs/notes.md:2: U+200B ZERO WIDTH SPACE"
    ]


@pytest.mark.parametrize(
    ("char", "expected"),
    [
        ("\ufeff", "U+FEFF ZERO WIDTH NO-BREAK SPACE"),
        ("\u00ad", "U+00AD SOFT HYPHEN"),
        ("\u200d", "U+200D ZERO WIDTH JOINER"),
        ("\u2060", "U+2060 WORD JOINER"),
        ("\u202e", "U+202E RIGHT-TO-LEFT OVERRIDE"),
        ("\U000e0041", "U+E0041 TAG LATIN CAPITAL LETTER A"),
        ("\x00", "U+0000 control character"),
        ("\x07", "U+0007 control character"),
        ("\x1b", "U+001B control character"),
        ("\x0b", "U+000B control character"),
        ("\x7f", "U+007F control character"),
        ("\x85", "U+0085 control character"),
    ],
)
def test_format_and_control_characters_are_reported(
    tmp_path: Path, char: str, expected: str
) -> None:
    path = plant(tmp_path, "README.md", f"first\nsecond\nthird {char} line\n")
    assert findings(path, tmp_path) == [f"README.md:3: {expected}"]


def test_every_occurrence_is_reported(tmp_path: Path) -> None:
    path = plant(tmp_path, "AGENTS.md", "a\u200bb\u200bc\nok\n\u2066x\n")
    assert findings(path, tmp_path) == [
        "AGENTS.md:1: U+200B ZERO WIDTH SPACE",
        "AGENTS.md:1: U+200B ZERO WIDTH SPACE",
        "AGENTS.md:3: U+2066 LEFT-TO-RIGHT ISOLATE",
    ]


def test_tab_lf_and_cr_are_allowed(tmp_path: Path) -> None:
    path = plant(tmp_path, "docs/a.md", "| a\t| b |\r\nline\nlast\r\n")
    assert findings(path, tmp_path) == []


def test_visible_non_ascii_text_is_allowed(tmp_path: Path) -> None:
    # Umlauts, arrows, dashes, the no-break space (Zs) and an escape written as text all pass.
    path = plant(tmp_path, "docs/b.md", "Grüße → ≤ 5\u00a0% \u2013 write \\u200b as text\n")
    assert findings(path, tmp_path) == []


def test_non_utf8_file_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "docs" / "c.md"
    path.parent.mkdir()
    path.write_bytes(b"caf\xe9\n")
    assert findings(path, tmp_path) == [
        "docs/c.md: not UTF-8 (invalid continuation byte at byte 3)"
    ]


def test_files_outside_the_scope_are_not_scanned(tmp_path: Path) -> None:
    plant(tmp_path, "fixtures/notes/x.md", "attack\u200btext\n")
    plant(tmp_path, "fixtures/http/x.body", "attack\u200btext\n")
    plant(tmp_path, "fixtures/README.md", "clean\n")
    assert [p.relative_to(tmp_path).as_posix() for p in doc_files(tmp_path)] == [
        "fixtures/README.md"
    ]
