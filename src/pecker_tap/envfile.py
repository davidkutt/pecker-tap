"""Read named settings from a local ``.env`` file (spec; pecker-drum ADR 0007).

Only the names the caller asks for are taken from the file; every other entry is skipped. A
non-empty value already in the environment wins over the file, an empty one counts as unset.
Nothing here prints or returns a value: the result only names what was loaded and what was skipped,
so a caller can report it without leaking a secret. An entry that is not ``NAME=value`` with a plain
name (for example a key pasted on a line of its own) is only counted, never named.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Collection, MutableMapping
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

_PLAIN_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


class EnvFileError(RuntimeError):
    """The file exists but cannot be read. The message never quotes the file's content."""


@dataclass(frozen=True, slots=True)
class EnvFileResult:
    found: bool = False
    loaded: tuple[str, ...] = ()
    """Names whose value came from the file (the environment had no value for them)."""
    ignored: tuple[str, ...] = ()
    """Other ``NAME=value`` entries with a plain name, skipped (names only)."""
    unnamed: int = 0
    """Entries without a plain ``NAME=value`` shape, skipped and never named."""
    readable_by_others: bool = False
    """The file's mode lets group or others read it (POSIX only)."""


def load_env_file(
    path: Path, names: Collection[str], environ: MutableMapping[str, str] | None = None
) -> EnvFileResult:
    """Copy ``names`` from the file at ``path`` into ``environ`` (default: ``os.environ``).

    A missing file is not an error. Values are stripped; an empty value in the file sets nothing.
    """
    target = os.environ if environ is None else environ
    if not path.is_file():
        return EnvFileResult()
    try:
        mode = path.stat().st_mode
        values = dotenv_values(path, interpolate=False)
    except UnicodeDecodeError:
        msg = f"{path} is not valid UTF-8"
        raise EnvFileError(msg) from None
    except OSError as exc:
        msg = f"cannot read {path}: {exc.strerror or type(exc).__name__}"
        raise EnvFileError(msg) from None
    loaded: list[str] = []
    ignored: list[str] = []
    unnamed = 0
    for name, value in values.items():
        if name in names:
            wanted = (value or "").strip()
            if wanted and not target.get(name, "").strip():
                target[name] = wanted
                loaded.append(name)
        elif value is not None and _PLAIN_NAME.fullmatch(name):
            ignored.append(name)
        else:
            unnamed += 1
    return EnvFileResult(
        found=True,
        loaded=tuple(loaded),
        ignored=tuple(sorted(ignored)),
        unnamed=unnamed,
        readable_by_others=os.name != "nt" and bool(mode & (stat.S_IRGRP | stat.S_IROTH)),
    )
