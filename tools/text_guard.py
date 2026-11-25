"""Guard against invisible characters: no Unicode format (Cf) or control (Cc) characters.

Tab, LF and CR are allowed. AGENTS.md asks for escapes instead (write ``\\u200b``, not the
character). One checker for every place the rule applies:

- ``docs [ROOT]``: ``README.md``, ``AGENTS.md``, ``SECURITY.md``, ``fixtures/README.md`` and every
  file under ``docs/``. ``tests/test_docs_text.py`` runs the same check in pytest.
- ``commits BASE HEAD``: every commit message in ``BASE..HEAD`` (CI, on pull requests).
- ``pr-text``: the pull request title and body from the environment variables ``PR_TITLE`` and
  ``PR_BODY``. CI passes them through ``env:``, never inside the shell command. The body of a pull
  request whose ``PR_AUTHOR`` is ``dependabot[bot]`` is skipped: it quotes third-party release
  notes, where emoji sequences carry U+200D ZERO WIDTH JOINER. Its title and commits are still
  checked.

Each finding names where it is, the line and the code point, for example
``docs/notes.md:2: U+200B ZERO WIDTH SPACE``. Exit code 0 means clean, 1 means findings.

Dev-only: this script is not part of the ``pecker_tap`` package and uses the standard library only.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import unicodedata
from collections.abc import Sequence
from pathlib import Path

FLAGGED_CATEGORIES = frozenset({"Cf", "Cc"})
ALLOWED = frozenset("\t\n\r")
SKIP_BODY_AUTHORS = frozenset({"dependabot[bot]"})
"""Pull request authors whose body quotes third-party text (checked through ``PR_AUTHOR``)."""
REPO_ROOT = Path(__file__).resolve().parents[1]


def text_findings(label: str, text: str) -> list[str]:
    """One ``label:line: U+XXXX NAME`` entry per format or control character in ``text``."""
    found: list[str] = []
    for number, line in enumerate(text.split("\n"), start=1):
        for char in line:
            category = unicodedata.category(char)
            if char in ALLOWED or category not in FLAGGED_CATEGORIES:
                continue
            name = unicodedata.name(char, "control character" if category == "Cc" else "unnamed")
            found.append(f"{label}:{number}: U+{ord(char):04X} {name}")
    return found


def doc_files(root: Path) -> list[Path]:
    """The docs the rule covers: four named files and every file under ``docs/``."""
    named = ["README.md", "AGENTS.md", "SECURITY.md", "fixtures/README.md"]
    files = [root / rel for rel in named]
    docs = root / "docs"
    if docs.is_dir():
        files += sorted(path for path in docs.rglob("*") if path.is_file())
    return [path for path in files if path.is_file()]


def findings(path: Path, root: Path) -> list[str]:
    """Findings for one file, labelled with its path relative to ``root``; non-UTF-8 is one."""
    rel = path.relative_to(root).as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return [f"{rel}: not UTF-8 ({exc.reason} at byte {exc.start})"]
    return text_findings(rel, text)


def message_findings(label: str, raw: bytes) -> list[str]:
    """Findings for a commit message given as raw bytes."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"{label}: not UTF-8 ({exc.reason} at byte {exc.start})"]
    return text_findings(label, text)


def _git(repo: Path, *args: str) -> bytes:
    git = shutil.which("git")
    if git is None:
        msg = "git not found"
        raise RuntimeError(msg)
    return subprocess.run(  # noqa: S603 - fixed git subcommands, arguments are never a shell string
        [git, "-C", str(repo), *args], check=True, capture_output=True
    ).stdout


def commit_findings(repo: Path, base: str, head: str) -> list[str]:
    """Findings in every commit message of ``base..head``, oldest commit first."""
    shas = _git(repo, "rev-list", "--reverse", f"{base}..{head}", "--").decode("ascii").split()
    found: list[str] = []
    for sha in shas:
        raw = _git(repo, "cat-file", "commit", sha)
        _headers, _, message = raw.partition(b"\n\n")
        found += message_findings(f"commit {sha[:12]}", message)
    return found


def pr_findings(title: str, body: str, author: str = "") -> list[str]:
    """Findings in a pull request title and body (the body is skipped for Dependabot)."""
    found = text_findings("PR title", title)
    if author not in SKIP_BODY_AUTHORS:
        found += text_findings("PR body", body)
    return found


def _report(found: Sequence[str], what: str) -> int:
    if not found:
        print(f"text guard: {what}: clean")
        return 0
    print(f"text guard: {what}: format or control characters, write them as escapes:")
    for line in found:
        print(f"  {line}")
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    sub = parser.add_subparsers(dest="command", required=True)
    docs = sub.add_parser("docs", help="scan the tracked docs")
    docs.add_argument("root", nargs="?", type=Path, default=REPO_ROOT)
    commits = sub.add_parser("commits", help="scan every commit message in BASE..HEAD")
    commits.add_argument("base")
    commits.add_argument("head")
    commits.add_argument("--repo", type=Path, default=Path.cwd())
    sub.add_parser("pr-text", help="scan PR_TITLE and PR_BODY from the environment")
    args = parser.parse_args(argv)

    if args.command == "docs":
        root: Path = args.root.resolve()
        found = [entry for path in doc_files(root) for entry in findings(path, root)]
        return _report(found, "docs")
    if args.command == "commits":
        found = commit_findings(args.repo, args.base, args.head)
        return _report(found, f"commits {args.base[:12]}..{args.head[:12]}")
    author = os.environ.get("PR_AUTHOR", "")
    if author in SKIP_BODY_AUTHORS:
        print(f"text guard: PR body skipped for {author} (third-party release notes)")
    found = pr_findings(os.environ.get("PR_TITLE", ""), os.environ.get("PR_BODY", ""), author)
    return _report(found, "PR title and body")


if __name__ == "__main__":
    sys.exit(main())
