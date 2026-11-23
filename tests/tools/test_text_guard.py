"""The text guard on commit messages and pull request text.

Every invisible character here is built from an escape, so this file itself stays clean. The commit
tests use a throwaway repository in ``tmp_path``; nothing is pushed anywhere.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
from text_guard import main, message_findings, pr_findings, text_findings

ZWSP = "\u200b"
GIT = shutil.which("git")


def test_commit_message_with_a_zero_width_space_fails_naming_the_code_point() -> None:
    raw = f"fix: split{ZWSP}word\n\nBody line.\n".encode()
    assert message_findings("commit 0123456789ab", raw) == [
        "commit 0123456789ab:1: U+200B ZERO WIDTH SPACE"
    ]


def test_pr_body_with_a_zero_width_space_fails_naming_the_code_point() -> None:
    body = f"## What changed\r\n\r\nsplit{ZWSP}word\r\n"
    assert pr_findings("V1: skeleton and claim extraction", body) == [
        "PR body:3: U+200B ZERO WIDTH SPACE"
    ]


def test_pr_title_is_checked_too() -> None:
    assert pr_findings(f"V1{ZWSP}", "clean") == ["PR title:1: U+200B ZERO WIDTH SPACE"]


def test_dependabot_body_is_skipped_but_its_title_is_not() -> None:
    body = f"Release notes with an emoji sequence: a\u200db{ZWSP}"
    assert pr_findings("ci(deps): bump x", body, "dependabot[bot]") == []
    assert pr_findings(f"ci(deps): bump{ZWSP} x", body, "dependabot[bot]") == [
        "PR title:1: U+200B ZERO WIDTH SPACE"
    ]
    # Any other author gets the body checked, including look-alike names.
    assert pr_findings("t", body, "dependabot") == [
        "PR body:1: U+200D ZERO WIDTH JOINER",
        "PR body:1: U+200B ZERO WIDTH SPACE",
    ]


def test_tab_cr_lf_and_visible_unicode_pass() -> None:
    text = "| a\t| b |\r\nGrüße → ≤ 5\u00a0% 🤖 and \\u200b written as text\n"
    assert text_findings("PR body", text) == []


def test_non_utf8_commit_message_is_reported() -> None:
    assert message_findings("commit abc", b"caf\xe9\n") == [
        "commit abc: not UTF-8 (invalid continuation byte at byte 3)"
    ]


def test_pr_text_command_reads_the_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PR_TITLE", "V1: skeleton and claim extraction")
    monkeypatch.setenv("PR_BODY", f"one\ntwo{ZWSP}\n")
    monkeypatch.delenv("PR_AUTHOR", raising=False)
    assert main(["pr-text"]) == 1
    assert "PR body:2: U+200B ZERO WIDTH SPACE" in capsys.readouterr().out
    monkeypatch.setenv("PR_BODY", "one\ntwo\n")
    assert main(["pr-text"]) == 0


def test_pr_text_command_skips_the_dependabot_body(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PR_TITLE", "ci(deps): bump the actions group")
    monkeypatch.setenv("PR_BODY", f"notes{ZWSP}")
    monkeypatch.setenv("PR_AUTHOR", "dependabot[bot]")
    assert main(["pr-text"]) == 0
    assert "PR body skipped for dependabot[bot]" in capsys.readouterr().out


def test_docs_command_scans_a_tree(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text(f"x\ny{ZWSP}\n", encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text(f"{ZWSP}\n", encoding="utf-8")
    assert main(["docs", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "SECURITY.md:1: U+200B ZERO WIDTH SPACE" in out
    assert "docs/a.md:2: U+200B ZERO WIDTH SPACE" in out


def _git(repo: Path, *args: str) -> str:
    assert GIT is not None
    config = [
        "-c",
        "user.name=test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.hooksPath=/dev/null",
    ]
    return subprocess.run(  # noqa: S603 - fixed git arguments in a temporary repository
        [GIT, "-C", str(repo), *config, *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _commit(repo: Path, message: str) -> str:
    message_file = repo.parent / "message.txt"
    message_file.write_text(message, encoding="utf-8")
    _git(repo, "commit", "--allow-empty", "--cleanup=verbatim", "-q", "-F", str(message_file))
    return _git(repo, "rev-parse", "HEAD")


@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_commits_command_checks_every_message_in_the_range(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    base = _commit(repo, f"docs: old commit with{ZWSP}a zero-width space before the range\n")
    clean = _commit(repo, "feat: clean subject\n\nClean body.\n")
    dirty = _commit(repo, f"fix: clean subject\n\nbody with{ZWSP}a zero-width space\n")

    assert main(["commits", base, clean, "--repo", str(repo)]) == 0
    capsys.readouterr()
    assert main(["commits", base, dirty, "--repo", str(repo)]) == 1
    out = capsys.readouterr().out
    assert f"commit {dirty[:12]}:3: U+200B ZERO WIDTH SPACE" in out
    assert base[:12] not in out.split("..")[-1]  # the commit before the range is not checked
    assert f"commit {base[:12]}" not in out
