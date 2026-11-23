"""Compare a run with the golden files in ``fixtures/expected/`` (V1 brief, deliverable 1).

``python tools/golden.py RUN [--expected DIR] [--update]``

``RUN`` is a run folder (it holds ``run.json``) or a folder with exactly one run folder in it, such
as the ``--out`` of the CI self-test. ``pack.yaml``, ``report.json`` and ``summary.md`` are compared
after replacing what changes from run to run: run ids, timestamps, ``checked_on``, the notes SHA,
the settings and config digests and model-call latencies. A mismatch prints a diff and exits 1.

``--update`` rewrites the golden files from the run (normalised the same way). Only use it on
purpose, and say why in the pull request that changes them.

Dev-only: not part of the ``pecker_tap`` package.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPECTED = REPO_ROOT / "fixtures" / "expected"
FILES = ("pack.yaml", "report.json", "summary.md")
VOLATILE = {
    "run_id": "<run_id>",
    "started_at": "<timestamp>",
    "finished_at": "<timestamp>",
    "checked_on": "<checked_on>",
    "notes_sha": "<notes_sha>",
    "settings_digest": "<digest>",
    "config_digest": "<digest>",
    "duration_s": 0,
    "latency_s": 0,
}
_SUMMARY = [
    (re.compile(r"^- Run: `[^`]*`", re.MULTILINE), "- Run: `<run_id>`"),
    (re.compile(r"^(- Notes: `[^`]*` at )`[^`]*`", re.MULTILINE), r"\1`<notes_sha>`"),
    (re.compile(r"^- Checked on: .*$", re.MULTILINE), "- Checked on: <checked_on>"),
]


def _scrub(value: object) -> object:
    if isinstance(value, dict):
        mapping = cast("dict[str, object]", value)
        return {
            key: (VOLATILE[key] if key in VOLATILE and item is not None else _scrub(item))
            for key, item in mapping.items()
        }
    if isinstance(value, list):
        return [_scrub(item) for item in cast("list[object]", value)]
    return value


def normalise(name: str, text: str) -> str:
    if name == "pack.yaml":
        data = _scrub(yaml.safe_load(text))
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
    if name == "report.json":
        return json.dumps(_scrub(json.loads(text)), indent=2, ensure_ascii=False) + "\n"
    for pattern, replacement in _SUMMARY:
        text = pattern.sub(replacement, text)
    return text


def find_run(path: Path) -> Path:
    if (path / "run.json").is_file():
        return path
    runs = sorted(p for p in path.iterdir() if (p / "run.json").is_file()) if path.is_dir() else []
    if len(runs) != 1:
        msg = f"{path}: expected one run folder, found {len(runs)}"
        raise SystemExit(msg)
    return runs[0]


def compare(run: Path, expected: Path, files: Sequence[str] = FILES) -> list[str]:
    """Diff lines for every file that differs (empty: the run matches the golden files)."""
    problems: list[str] = []
    for name in files:
        want_path, got_path = expected / name, run / name
        if not want_path.is_file() or not got_path.is_file():
            problems.append(
                f"{name}: missing in {'expected' if not want_path.is_file() else 'run'}"
            )
            continue
        want = normalise(name, want_path.read_text(encoding="utf-8"))
        got = normalise(name, got_path.read_text(encoding="utf-8"))
        if want != got:
            problems += list(
                difflib.unified_diff(
                    want.splitlines(),
                    got.splitlines(),
                    f"expected/{name}",
                    f"run/{name}",
                    lineterm="",
                )
            )
    return problems


def update(run: Path, expected: Path) -> None:
    expected.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        text = normalise(name, (run / name).read_text(encoding="utf-8"))
        (expected / name).write_text(text, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("run", type=Path, help="a run folder, or a folder with one run folder")
    parser.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED)
    parser.add_argument("--update", action="store_true", help="rewrite the golden files")
    args = parser.parse_args(argv)
    run = find_run(args.run)
    if args.update:
        update(run, args.expected)
        print(f"golden: rewrote {', '.join(FILES)} in {args.expected} from {run}")
        return 0
    problems = compare(run, args.expected)
    if problems:
        print(f"golden: {run} differs from {args.expected}:")
        print("\n".join(problems))
        return 1
    print(f"golden: {run} matches {args.expected}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
