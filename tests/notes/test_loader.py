import shutil
import subprocess
from pathlib import Path

import pytest

from pecker_tap.notes.loader import (
    FrontmatterError,
    load_notes,
    notes_sha,
    parse_note,
    split_sections,
)


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")
    return path


# --- frontmatter -------------------------------------------------------------------------------


def test_frontmatter_keeps_known_keys_and_names_unknown_ones() -> None:
    note = parse_note(
        "a.md",
        "---\n"
        "id: note-1\n"
        "sources:\n  - https://vendor.example/advisory\n  - {url: https://b.example/x, title: B}\n"
        "cve: CVE-2099-0001\n"
        "ghsa: [GHSA-0000-0000-0001]\n"
        "decision: awaiting-david\n"
        "review: 2026-11-20\n"
        "tags: [ai]\n"
        "zz_custom: {nested: true}\n"
        "---\n"
        "# Title\n",
    )
    fm = note.frontmatter
    assert fm.id == "note-1"
    assert fm.sources == ("https://vendor.example/advisory", "https://b.example/x")
    assert fm.cve == ("CVE-2099-0001",)  # a scalar becomes a one-item list
    assert fm.ghsa == ("GHSA-0000-0000-0001",)
    assert fm.review == "2026-11-20"  # YAML dates come back as ISO strings
    assert fm.unknown_keys == ("tags", "zz_custom")
    assert note.awaiting_decision
    assert note.frontmatter_lines == (1, 12)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("# Only a body\n", None),
        ("---\n---\n# Empty block\n", (1, 2)),
        ("---\n...\n# Closed with dots\n", (1, 2)),
        ("﻿---\nid: x\n---\nbody\n", (1, 3)),  # byte order mark dropped first
        ("---\r\nid: x\r\n---\r\nbody\r\n", (1, 3)),  # CRLF
    ],
)
def test_frontmatter_block_variants(text: str, expected: tuple[int, int] | None) -> None:
    assert parse_note("a.md", text).frontmatter_lines == expected


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("---\nid: x\n# never closed\n", "never closed"),
        ("---\nid: [unclosed\n---\n", "not valid YAML"),
        ("---\n- a list\n---\n", "not a mapping"),
    ],
)
def test_broken_frontmatter_raises(text: str, message: str) -> None:
    with pytest.raises(FrontmatterError, match=message):
        parse_note("a.md", text)


def test_odd_values_of_known_keys_become_warnings_not_errors() -> None:
    note = parse_note("a.md", "---\ncve: [CVE-2099-0001, [nested]]\nid: {a: b}\n---\nx\n")
    assert note.frontmatter.cve == ("CVE-2099-0001",)
    assert note.frontmatter.id is None
    assert len(note.warnings) == 2


def test_null_frontmatter_values() -> None:
    fm = parse_note("a.md", "---\nsources:\ncve: ~\ndecision:\n---\n").frontmatter
    assert (fm.sources, fm.cve, fm.decision) == ((), (), None)


# --- sections ----------------------------------------------------------------------------------


def test_sections_have_file_line_numbers_including_frontmatter() -> None:
    text = (
        "---\n"  # 1
        "id: x\n"  # 2
        "---\n"  # 3
        "Intro line.\n"  # 4
        "\n"  # 5
        "# Advisory\n"  # 6
        "Fixed in 3.8.0.\n"  # 7
        "## Details ##\n"  # 8
        "```bash\n"  # 9
        "# not a heading inside a fence\n"  # 10
        "```\n"  # 11
        "Score 7.5.\n"  # 12
        "\n"  # 13
    )
    note = parse_note("a.md", text)
    assert [(s.heading, s.level, s.first_line, s.last_line) for s in note.sections] == [
        (None, 0, 4, 5),
        ("Advisory", 1, 6, 7),
        ("Details", 2, 8, 12),
    ]
    assert note.line_span(7, 7) == "Fixed in 3.8.0."
    assert note.line_span(12, 12) == "Score 7.5."


def test_tilde_fences_and_longer_closing_fences() -> None:
    lines = ["~~~~", "# inside", "~~~", "# still inside", "~~~~~", "# Real"]
    sections = split_sections(lines, 1)
    assert [(s.heading, s.first_line) for s in sections] == [(None, 1), ("Real", 6)]


def test_hash_without_space_is_not_a_heading_and_empty_heading_is() -> None:
    sections = split_sections(["#hashtag", "#", "text"], 1)
    assert [(s.heading, s.first_line, s.last_line) for s in sections] == [
        (None, 1, 1),
        ("", 2, 3),
    ]


def test_blank_body_has_no_sections_and_line_span_rejects_bad_ranges() -> None:
    note = parse_note("a.md", "---\nid: x\n---\n\n\n")
    assert note.sections == ()
    assert note.line_span(0, 1) == ""
    assert note.line_span(3, 2) == ""
    assert note.line_span(1, 99) == ""


# --- files -------------------------------------------------------------------------------------


def test_load_skips_hidden_and_non_markdown_and_filters_by_glob(tmp_path: Path) -> None:
    write(tmp_path, "b.md", "# B\n")
    write(tmp_path, "advisories/a.md", "# A\n")
    write(tmp_path, "advisories/deep/c.md", "# C\n")
    write(tmp_path, ".obsidian/workspace.md", "# hidden folder\n")
    write(tmp_path, "advisories/.draft.md", "# hidden file\n")
    write(tmp_path, "notes.txt", "not markdown\n")
    everything = load_notes(tmp_path)
    assert [n.path for n in everything.notes] == [
        "advisories/a.md",
        "advisories/deep/c.md",
        "b.md",
    ]
    selected = load_notes(tmp_path, ["advisories/**"])
    assert [n.path for n in selected.notes] == ["advisories/a.md", "advisories/deep/c.md"]
    assert [n.path for n in load_notes(tmp_path, ["*.md"]).notes] == ["b.md"]


def test_a_broken_note_is_reported_and_the_rest_loads(tmp_path: Path) -> None:
    write(tmp_path, "good.md", "# Good\n")
    write(tmp_path, "broken.md", "---\nid: [\n---\n")
    (tmp_path / "latin1.md").write_bytes(b"caf\xe9\n")
    result = load_notes(tmp_path)
    assert [n.path for n in result.notes] == ["good.md"]
    assert [(e.path, e.message) for e in result.errors] == [
        ("broken.md", "frontmatter is not valid YAML (line 2)"),
        ("latin1.md", "not UTF-8 (byte 3)"),
    ]


def test_symlink_outside_the_root_is_skipped(tmp_path: Path) -> None:
    outside = write(tmp_path, "outside/secret.md", "# Secret\n")
    root = tmp_path / "notes"
    write(root, "a.md", "# A\n")
    (root / "link.md").symlink_to(outside)
    assert [n.path for n in load_notes(root).notes] == ["a.md"]


def _git(repo: Path, *args: str) -> str:
    git = shutil.which("git")
    assert git is not None
    identity = ["-c", "user.name=t", "-c", "user.email=t@t.invalid"]
    done = subprocess.run(  # noqa: S603 - fixed git subcommands in a temporary repository
        [git, "-C", str(repo), *identity, *args], check=True, capture_output=True
    )
    return done.stdout.decode().strip()


def test_notes_sha_reads_head_or_says_unknown(tmp_path: Path) -> None:
    assert notes_sha(tmp_path) == "unknown"
    write(tmp_path, "a.md", "# A\n")
    _git(tmp_path, "init", "-q")
    assert notes_sha(tmp_path) == "unknown"  # no commit yet
    _git(tmp_path, "add", "a.md")
    _git(tmp_path, "commit", "-q", "-m", "init")
    assert notes_sha(tmp_path) == _git(tmp_path, "rev-parse", "HEAD")
