"""Command line: ``tap run``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from pecker_tap import __version__

ENV_FILE = Path(".env")
"""Read from the working directory, and only when a live switch is set (spec)."""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tap", allow_abbrev=False)
    parser.add_argument("--version", action="version", version=f"tap {__version__}")
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
